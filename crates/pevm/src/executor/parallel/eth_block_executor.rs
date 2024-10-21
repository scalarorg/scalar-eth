//! Ethereum block executor.

use super::{types::BlockExecutionRequest, ParallelEvmContext};
use crate::{
    dao_fork::{DAO_HARDFORK_BENEFICIARY, DAO_HARDKFORK_ACCOUNTS},
    executor::eth_evm_executor::EthExecuteOutput,
};
use alloc::sync::Arc;
use alloy_primitives::U256;
use core::fmt::Display;
use reth_chainspec::{ChainSpec, EthereumHardforks};
use reth_evm::{
    execute::{
        BlockExecutionError, BlockExecutionInput, BlockExecutionOutput, BlockValidationError,
        Executor, ProviderError,
    },
    system_calls::{NoopHook, OnStateHook},
    ConfigureEvm,
};
use reth_execution_errors::InternalBlockExecutionError;
use reth_primitives::{BlockWithSenders, EthereumHardfork, Header, Receipt};
use reth_revm::{
    db::{states::bundle_state::BundleRetention, State},
    state_change::post_block_balance_increments,
};
use reth_tracing::tracing::{debug, info};
use revm_primitives::{db::Database, BlockEnv, CfgEnvWithHandlerCfg, EnvWithHandlerCfg};
use tokio::sync::{mpsc, oneshot};
/// A basic Ethereum block executor.
///
/// Expected usage:
/// - Create a new instance of the executor.
/// - Execute the block.
#[derive(Debug)]
pub struct ParallelEthBlockExecutor<EvmConfig, DB> {
    /// Chain specific evm config that's used to execute a block.
    // executor: ParallelEthEvmExecutor<EvmConfig>,
    chain_spec: Arc<ChainSpec>,
    evm_config: EvmConfig,
    tx_execution_request: mpsc::UnboundedSender<BlockExecutionRequest>,
    /// The state to use for execution
    pub(super) state: State<DB>,
}

impl<EvmConfig, DB> ParallelEthBlockExecutor<EvmConfig, DB> {
    /// Creates a new Ethereum block executor.
    pub fn new(
        chain_spec: Arc<ChainSpec>,
        evm_config: EvmConfig,
        tx_execution_request: mpsc::UnboundedSender<BlockExecutionRequest>,
        state: State<DB>,
    ) -> Self {
        Self {
            //executor: ParallelEthEvmExecutor::new(chain_spec, evm_config, tx_execution_request),
            chain_spec,
            evm_config,
            tx_execution_request,
            state,
        }
    }

    #[inline]
    pub(super) fn chain_spec(&self) -> &ChainSpec {
        &self.chain_spec
    }

    /// Returns mutable reference to the state that wraps the underlying database.
    #[allow(unused)]
    pub(super) fn state_mut(&mut self) -> &mut State<DB> {
        &mut self.state
    }
}

impl<EvmConfig, DB> ParallelEthBlockExecutor<EvmConfig, DB>
where
    EvmConfig:
        for<'a> ConfigureEvm<Header = Header, DefaultExternalContext<'a> = ParallelEvmContext>,
    DB: Database<Error: Into<ProviderError> + Display>,
{
    /// Configures a new evm configuration and block environment for the given block.
    ///
    /// # Caution
    ///
    /// This does not initialize the tx environment.
    fn evm_env_for_block(&self, header: &Header, total_difficulty: U256) -> EnvWithHandlerCfg {
        let mut cfg = CfgEnvWithHandlerCfg::new(Default::default(), Default::default());
        let mut block_env = BlockEnv::default();
        self.evm_config.fill_cfg_and_block_env(&mut cfg, &mut block_env, header, total_difficulty);

        EnvWithHandlerCfg::new_with_cfg_env(cfg, block_env, Default::default())
    }

    /// Convenience method to invoke `execute_without_verification_with_state_hook` setting the
    /// state hook as `None`.
    pub(super) fn execute_without_verification(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<EthExecuteOutput, BlockExecutionError> {
        self.execute_without_verification_with_state_hook(block, total_difficulty, None::<NoopHook>)
    }

    /// Execute a single block and apply the state changes to the internal state.
    ///
    /// Returns the receipts of the transactions in the block, the total gas used and the list of
    /// EIP-7685 [requests](Request).
    ///
    /// Returns an error if execution fails.
    fn execute_without_verification_with_state_hook<F>(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
        _state_hook: Option<F>,
    ) -> Result<EthExecuteOutput, BlockExecutionError>
    where
        F: OnStateHook,
    {
        // 1. prepare state on new block
        self.on_new_block(&block.header);
        // 2. Send execution request to the execution thread
        let env = self.evm_env_for_block(&block.header, total_difficulty);
        let (result_sender, mut result_receiver) = oneshot::channel();
        let block_request =
            BlockExecutionRequest::new(block.clone(), env, total_difficulty, result_sender);
        self.tx_execution_request.send(block_request).map_err(|e| {
            BlockExecutionError::Internal(InternalBlockExecutionError::Other(Box::new(e)))
        })?;
        // 3. Waiting for execution result
        // Loop until the execution is complete
        while let Ok(output) = result_receiver.try_recv() {
            // 3. apply post execution changes
            self.post_execution(block, total_difficulty)?;
            return Ok(output);
        }
        // 2. configure the evm and execute
        // let env = self.evm_env_for_block(&block.header, total_difficulty);
        // let output = {
        //     let evm = self.evm_config.evm_with_env(&mut self.state, env);
        //     self.executor.execute_state_transitions(block, evm, state_hook)
        // };

        Err(BlockExecutionError::Internal(InternalBlockExecutionError::msg(
            "Execution result not found",
        )))
    }

    /// Apply settings before a new block is executed.
    pub(crate) fn on_new_block(&mut self, header: &Header) {
        // Set state clear flag if the block is after the Spurious Dragon hardfork.
        let state_clear_flag = self.chain_spec().is_spurious_dragon_active_at_block(header.number);
        self.state.set_state_clear_flag(state_clear_flag);
    }

    /// Apply post execution state changes that do not require an [EVM](Evm), such as: block
    /// rewards, withdrawals, and irregular DAO hardfork state change
    pub fn post_execution(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<(), BlockExecutionError> {
        let mut balance_increments =
            post_block_balance_increments(self.chain_spec(), block, total_difficulty);

        // Irregular state change at Ethereum DAO hardfork
        if self.chain_spec().fork(EthereumHardfork::Dao).transitions_at_block(block.number) {
            // drain balances from hardcoded addresses.
            let drained_balance: u128 = self
                .state
                .drain_balances(DAO_HARDKFORK_ACCOUNTS)
                .map_err(|_| BlockValidationError::IncrementBalanceFailed)?
                .into_iter()
                .sum();

            // return balance to DAO beneficiary.
            *balance_increments.entry(DAO_HARDFORK_BENEFICIARY).or_default() += drained_balance;
        }
        // increment balances
        self.state
            .increment_balances(balance_increments)
            .map_err(|_| BlockValidationError::IncrementBalanceFailed)?;

        Ok(())
    }
}

impl<EvmConfig, DB> Executor<DB> for ParallelEthBlockExecutor<EvmConfig, DB>
where
    EvmConfig:
        for<'a> ConfigureEvm<Header = Header, DefaultExternalContext<'a> = ParallelEvmContext>,
    DB: Database<Error: Into<ProviderError> + Display>,
{
    type Input<'b> = BlockExecutionInput<'b, BlockWithSenders>;
    type Output = BlockExecutionOutput<Receipt>;
    type Error = BlockExecutionError;

    /// Executes the block and commits the changes to the internal state.
    ///
    /// Returns the receipts of the transactions in the block.
    ///
    /// Returns an error if the block could not be executed or failed verification.
    fn execute(mut self, input: Self::Input<'_>) -> Result<Self::Output, Self::Error> {
        let BlockExecutionInput { block, total_difficulty } = input;
        let EthExecuteOutput { receipts, requests, gas_used } =
            self.execute_without_verification(block, total_difficulty)?;

        // NOTE: we need to merge keep the reverts for the bundle retention
        self.state.merge_transitions(BundleRetention::Reverts);

        Ok(BlockExecutionOutput { state: self.state.take_bundle(), receipts, requests, gas_used })
    }

    fn execute_with_state_closure<F>(
        mut self,
        input: Self::Input<'_>,
        mut witness: F,
    ) -> Result<Self::Output, Self::Error>
    where
        F: FnMut(&State<DB>),
    {
        let BlockExecutionInput { block, total_difficulty } = input;
        let EthExecuteOutput { receipts, requests, gas_used } =
            self.execute_without_verification(block, total_difficulty)?;

        // NOTE: we need to merge keep the reverts for the bundle retention
        self.state.merge_transitions(BundleRetention::Reverts);
        witness(&self.state);
        Ok(BlockExecutionOutput { state: self.state.take_bundle(), receipts, requests, gas_used })
    }

    fn execute_with_state_hook<F>(
        mut self,
        input: Self::Input<'_>,
        state_hook: F,
    ) -> Result<Self::Output, Self::Error>
    where
        F: OnStateHook,
    {
        let BlockExecutionInput { block, total_difficulty } = input;
        let EthExecuteOutput { receipts, requests, gas_used } = self
            .execute_without_verification_with_state_hook(
                block,
                total_difficulty,
                Some(state_hook),
            )?;

        // NOTE: we need to merge keep the reverts for the bundle retention
        self.state.merge_transitions(BundleRetention::Reverts);
        Ok(BlockExecutionOutput { state: self.state.take_bundle(), receipts, requests, gas_used })
    }
}
