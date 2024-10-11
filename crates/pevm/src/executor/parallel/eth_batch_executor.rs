//! Ethereum block executor.

use crate::executor::eth_evm_executor::EthExecuteOutput;

use super::{ParallelEthBlockExecutor, ParallelEvmContext};
use alloy_primitives::BlockNumber;
use core::fmt::Display;
use reth_ethereum_consensus::validate_block_post_execution;
use reth_evm::{
    execute::{BatchExecutor, BlockExecutionError, BlockExecutionInput, ProviderError},
    ConfigureEvm,
};
use reth_execution_types::ExecutionOutcome;
use reth_primitives::{BlockWithSenders, Header};
use reth_prune_types::PruneModes;
use reth_revm::{batch::BlockBatchRecord, db::State};
use revm_primitives::db::Database;
/// An executor for a batch of blocks.
///
/// State changes are tracked until the executor is finalized.
#[derive(Debug)]
pub struct ParallelEthBatchExecutor<EvmConfig, DB> {
    /// The executor used to execute single blocks
    ///
    /// All state changes are committed to the [State].
    pub(crate) executor: ParallelEthBlockExecutor<EvmConfig, DB>,
    /// Keeps track of the batch and records receipts based on the configured prune mode
    pub(crate) batch_record: BlockBatchRecord,
}

impl<EvmConfig, DB> ParallelEthBatchExecutor<EvmConfig, DB> {
    /// Returns mutable reference to the state that wraps the underlying database.
    #[allow(unused)]
    pub(crate) fn state_mut(&mut self) -> &mut State<DB> {
        self.executor.state_mut()
    }
}

impl<EvmConfig, DB> BatchExecutor<DB> for ParallelEthBatchExecutor<EvmConfig, DB>
where
    EvmConfig:
        for<'a> ConfigureEvm<Header = Header, DefaultExternalContext<'a> = ParallelEvmContext>,
    DB: Database<Error: Into<ProviderError> + Display>,
{
    type Input<'b> = BlockExecutionInput<'b, BlockWithSenders>;
    type Output = ExecutionOutcome;
    type Error = BlockExecutionError;

    fn execute_and_verify_one(&mut self, input: Self::Input<'_>) -> Result<(), Self::Error> {
        let BlockExecutionInput { block, total_difficulty } = input;

        if self.batch_record.first_block().is_none() {
            self.batch_record.set_first_block(block.number);
        }

        let EthExecuteOutput { receipts, requests, gas_used: _ } =
            self.executor.execute_without_verification(block, total_difficulty)?;

        validate_block_post_execution(block, self.executor.chain_spec(), &receipts, &requests)?;

        // prepare the state according to the prune mode
        let retention = self.batch_record.bundle_retention(block.number);
        self.executor.state.merge_transitions(retention);

        // store receipts in the set
        self.batch_record.save_receipts(receipts)?;

        // store requests in the set
        self.batch_record.save_requests(requests);

        Ok(())
    }

    fn finalize(mut self) -> Self::Output {
        ExecutionOutcome::new(
            self.executor.state.take_bundle(),
            self.batch_record.take_receipts(),
            self.batch_record.first_block().unwrap_or_default(),
            self.batch_record.take_requests(),
        )
    }

    fn set_tip(&mut self, tip: BlockNumber) {
        self.batch_record.set_tip(tip);
    }

    fn set_prune_modes(&mut self, prune_modes: PruneModes) {
        self.batch_record.set_prune_modes(prune_modes);
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.executor.state.bundle_state.size_hint())
    }
}
