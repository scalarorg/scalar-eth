//! Parallel Ethereum evm executor.

use ahash::AHashMap;
use alloc::{boxed::Box, vec, vec::Vec};
use arc_swap::{ArcSwap, ArcSwapOption};
use async_scoped::AsyncStdScope;
use core::fmt::Display;
use reth_chainspec::{ChainSpec, EthereumHardforks};
use reth_evm::{
    execute::{BlockExecutionError, ProviderError},
    system_calls::{OnStateHook, SystemCaller},
    ConfigureEvm,
};
use reth_execution_errors::{BlockValidationError, InternalBlockExecutionError};
use reth_primitives::{BlockWithSenders, Header, Receipt, TxType};
use reth_revm::{db::State, Evm};
use reth_tracing::tracing::{debug, info};
use revm::{DatabaseCommit, InMemoryDB};
use revm_primitives::{db::Database, EnvWithHandlerCfg, ResultAndState, TxEnv, U256};
use std::{
    sync::{Arc, Mutex, OnceLock},
    thread,
};
use tokio::{
    io,
    runtime::{Builder, Runtime},
    sync::{mpsc, RwLock},
};

use crate::executor::{
    eth_evm_executor::EthExecuteOutput,
    parallel::types::{EvmAccount, MemoryEntry, MemoryValue},
};

use super::{
    chain::{PevmChain, PevmEthereum},
    context::ParallelEvmContextTrait,
    evm::{
        BlockContext, EvmWrapper, ExecutionError, PevmTxExecutionResult, VmExecutionError,
        VmExecutionResult,
    },
    memory::MvMemory,
    storage::Storage,
    types::{BlockExecutionRequest, MemoryLocation, Task, TxVersion},
    Scheduler,
};
/// Errors when executing a block with pevm.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PevmError<C: PevmChain> {
    /// Cannot derive the chain spec from the block header.
    BlockSpecError(C::BlockSpecError),
    /// Transactions lack information for execution.
    MissingTransactionData,
    /// Invalid input transaction.
    InvalidTransaction(C::TransactionParsingError),
    /// Storage error.
    // TODO: More concrete types than just an arbitrary string.
    StorageError(String),
    /// EVM execution error.
    // TODO: More concrete types than just an arbitrary string.
    ExecutionError(String),
    /// Impractical errors that should be unreachable.
    /// The library has bugs if this is yielded.
    UnreachableError,
}

#[derive(Debug)]
pub(super) enum AbortReason {
    FallbackToSequential,
    ExecutionError(ExecutionError),
}

// TODO: Better implementation
#[derive(Debug)]
struct AsyncDropper<T> {
    sender: std::sync::mpsc::Sender<T>,
    _handle: thread::JoinHandle<()>,
}

impl<T: Send + 'static> Default for AsyncDropper<T> {
    fn default() -> Self {
        let (sender, receiver) = std::sync::mpsc::channel();
        Self { sender, _handle: std::thread::spawn(move || receiver.into_iter().for_each(drop)) }
    }
}

impl<T> AsyncDropper<T> {
    fn drop(&self, t: T) {
        // TODO: Better error handling
        self.sender.send(t).unwrap();
    }
}

/// Helper container type for EVM with chain spec.
#[derive(Debug)]
pub struct ParallelEthEvmExecutor<EvmConfig, C: PevmChain, S: Storage> {
    /// The chainspec
    chain_spec: Arc<ChainSpec>,
    chain: Arc<C>,
    /// How to create an EVM.
    evm_config: EvmConfig,
    rx_execution_request: mpsc::UnboundedReceiver<BlockExecutionRequest>,
    scheduler: Arc<ArcSwapOption<Scheduler>>,
    mv_memory: Arc<ArcSwapOption<MvMemory>>,
    block_context: Arc<ArcSwapOption<BlockContext>>,
    //Inmemory storage for store and load account state
    state: Arc<S>,
    hasher: Arc<ahash::RandomState>,
    execution_results: Vec<Mutex<Option<PevmTxExecutionResult>>>,
    dropper: AsyncDropper<(MvMemory, Scheduler, Vec<(TxEnv, TxType)>)>,
}
impl<EvmConfig, C: PevmChain, S: Storage + Send + Sync + 'static>
    ParallelEthEvmExecutor<EvmConfig, C, S>
{
    /// Create a new ParallelEthEvmExecutor
    pub fn new(
        chain_spec: Arc<ChainSpec>,
        chain: Arc<C>,
        evm_config: EvmConfig,
        state: Arc<S>,
        rx_execution_request: mpsc::UnboundedReceiver<BlockExecutionRequest>,
    ) -> Self {
        //Create common memory for all threads
        let mv_memory = Arc::new(ArcSwapOption::empty());
        let scheduler = Arc::new(ArcSwapOption::empty());
        let block_context = Arc::new(ArcSwapOption::empty());
        Self {
            chain_spec,
            chain,
            evm_config,
            rx_execution_request,
            scheduler,
            state,
            mv_memory,
            block_context,
            execution_results: Vec::new(),
            hasher: Arc::new(ahash::RandomState::new()),
            dropper: AsyncDropper::default(),
        }
    }
}
impl<EvmConfig, C, S> ParallelEthEvmExecutor<EvmConfig, C, S>
where
    EvmConfig: ConfigureEvm<Header = Header>,
    C: PevmChain + Send + Sync + 'static,
    S: Storage + Send + Sync + 'static,
{
    /// Start the executor thread
    /// Spawns a new threads to execute the block in parallel
    pub async fn start(&mut self, thread_count: usize) {
        let mut handles = Vec::new();
        let mut evms = Vec::new();
        for i in 0..thread_count {
            let hasher = self.hasher.clone();
            let state = self.state.clone();
            let mv_memory = self.mv_memory.clone();
            let scheduler = self.scheduler.clone();
            let block_context = self.block_context.clone();
            let chain = self.chain.clone();
            let evm_wapper = self.create_evm_wrapper(self.chain.clone(), i);
            evms.push(evm_wapper);
            // let handle = tokio::spawn(async move {
            //     debug!(target: "scalaris::pevm", "Started excution worker {}", i);
            //     //let sub_hasher = hasher;
            //     //let sub_state = state;
            //     //let sub_mv_memory = mv_memory;
            //     //let sub_scheduler = scheduler;
            //     //let sub_block_context = block_context;
            //     //let sub_chain = chain;
            //     let evm_wapper =
            //         EvmWrapper::new(i, hasher, state, mv_memory, scheduler, block_context, chain);
            //     evm_wapper.start();
            // });
            // handles.push(handle);
        }
        for evm in evms.iter() {
            let evm_wapper = evm.clone();
            let handle = tokio::spawn(async move {
                debug!(target: "scalaris::pevm", "Started excution worker {}", evm_wapper.get_index());
                evm_wapper.start();
            });
            handles.push(handle);
        }
        //Loop to receive block execution request
        while let Some(BlockExecutionRequest { block, mut env, total_difficulty, result_sender }) =
            self.rx_execution_request.recv().await
        {
            //1. Create block env and tx envs, put them into mv memory
            self.prepare_block_execution(block, &mut env);
            //2. Loop throw all evm wrappers and collect results
            //3. Send results to result sender
            //result_sender.send(EthExecuteOutput::new(receipts, total_difficulty))
        }
    }
    fn create_evm_wrapper(&mut self, chain: Arc<C>, index: usize) -> Arc<EvmWrapper<C, S>> {
        Arc::new(EvmWrapper::new(
            index,
            self.hasher.clone(),
            self.state.clone(),
            self.mv_memory.clone(),
            self.scheduler.clone(),
            self.block_context.clone(),
            chain,
        ))
    }
    /// Creates tokio runtime based on the available parallelism.
    fn prepare_runtime(&self, workers: usize) -> io::Result<Runtime> {
        Builder::new_multi_thread()
            .worker_threads(workers)
            .thread_name("parallel_evm")
            .thread_stack_size(3 * 1024 * 1024)
            .build()
    }
    /// Prepare block execution environmet for each incomming block
    fn prepare_block_execution(
        &self,
        block: BlockWithSenders,
        env: &mut EnvWithHandlerCfg,
    ) -> Result<(), C::BlockSpecError> {
        let block_size = block.transactions_with_sender().count();
        // Create new mv memory store all block txs
        self.evm_config.fill_block_env(&mut env.block, &block.header, true);
        let mut txs = Vec::with_capacity(block_size);
        let mut tx_types = Vec::with_capacity(block_size);
        for (address, transaction) in block.transactions_with_sender() {
            let mut tx = env.tx.clone();
            self.evm_config.fill_tx_env(&mut tx, transaction, *address);
            txs.push(tx);
            tx_types.push(transaction.tx_type());
        }
        let mv_memory =
            self.chain.build_mv_memory(self.hasher.as_ref(), &env.block, txs.as_slice());
        //2. Update shared mv memory, so all evm wrappers can access to new block txs
        self.mv_memory.store(Some(Arc::new(mv_memory)));
        //3. Reset scheduler
        self.scheduler.store(Some(Arc::new(Scheduler::new(0))));
        //4. Update input_txs with combined transaction and type information
        let combined_txs = txs.into_iter().zip(tx_types).collect::<Vec<_>>();
        let spec_id = self.chain.get_block_spec_from_consensus_header(&block.header)?;
        let block_context = BlockContext::new(block, combined_txs, spec_id, env.block.clone());

        self.block_context.store(Some(Arc::new(block_context)));
        Ok(())
    }
}
// impl<EvmConfig, S: Storage> ParallelEthEvmExecutor<EvmConfig, S>
// where
//     EvmConfig: ConfigureEvm<Header = Header>,
// {
//     /// Executes the transactions in the block and returns the receipts of the transactions in the
//     /// block, the total gas used and the list of EIP-7685 [requests](Request).
//     ///
//     /// This applies the pre-execution and post-execution changes that require an [EVM](Evm), and
//     /// executes the transactions.
//     ///
//     /// # Note
//     ///
//     /// It does __not__ apply post-execution changes that do not require an [EVM](Evm), for that see
//     /// [`EthBlockExecutor::post_execution`].
//     pub(super) fn execute_state_transitions<Ext, DB, F>(
//         &self,
//         block: &BlockWithSenders,
//         mut evm: Evm<'_, Ext, &mut State<DB>>,
//         state_hook: Option<F>,
//     ) -> Result<EthExecuteOutput, BlockExecutionError>
//     where
//         Ext: ParallelEvmContextTrait,
//         DB: Database,
//         DB::Error: Into<ProviderError> + Display,
//         F: OnStateHook,
//     {
//         let mut system_caller =
//             SystemCaller::new(&self.evm_config, &self.chain_spec).with_state_hook(state_hook);
//         // apply pre execution changes
//         system_caller.apply_pre_execution_changes(block, &mut evm)?;
//         let block_env = evm.block_mut();
//         self.evm_config.fill_block_env(block_env, &block.header, true);
//         evm.context.external.set_block_hash(block.number, block.parent_hash);
//         // Execute transactions
//         let result = self.parallel_transition::<Ext, DB, F>(block, evm, system_caller);
//         if let Err(err) = &result {
//             info!(target: "scalaris::pevm", "parallel transition error: {:?}", err);
//         }
//         result
//     }

//     fn parallel_transition<Ext, DB, F>(
//         &self,
//         block: &BlockWithSenders,
//         mut evm: Evm<'_, Ext, &mut State<DB>>,
//         mut system_caller: SystemCaller<'_, EvmConfig, &Arc<ChainSpec>, F>,
//     ) -> Result<EthExecuteOutput, BlockExecutionError>
//     where
//         Ext: ParallelEvmContextTrait,
//         DB: Database,
//         DB::Error: Into<ProviderError> + Display,
//         F: OnStateHook,
//     {
//         // Use tokio runtime to execute transactions in parallel
//         // let runtime: Runtime = self.prepare_runtime(concurrency_level).map_err(|err| {
//         //     BlockExecutionError::Internal(InternalBlockExecutionError::Other(Box::new(err)))
//         // })?;
//         let block_env = evm.block();
//         let block_size = block.transactions_with_sender().count();
//         debug!(target: "scalaris::pevm", "parallel transition with block size: {}", block_size);
//         let scheduler = Scheduler::new(block_size);

//         let chain = PevmEthereum::mainnet();
//         // Initialize empty memory for WrapperEvm
//         let mv_memory = MvMemory::new(block_size, [], []);
//         let mut txs = Vec::with_capacity(block_size);
//         for (address, transaction) in block.transactions_with_sender() {
//             let mut tx = evm.tx().clone();
//             let tx_type = transaction.tx_type();
//             self.evm_config.fill_tx_env(&mut tx, transaction, *address);
//             txs.push((tx, tx_type));
//         }

//         let storage = evm.context.external.storage();
//         let evm_wapper = EvmWrapper::new(
//             &self.hasher,
//             storage,
//             &mv_memory,
//             &chain,
//             block_env,
//             txs.as_slice(),
//             evm.spec_id(),
//         );
//         let mut abort_reason = OnceLock::new();
//         for i in 0..4 {
//             unsafe {
//                 AsyncStdScope::scope(|scope| {
//                     // Use the scope to spawn the future.
//                     scope.spawn(async {
//                         debug!(target: "scalaris::pevm", "Started excution worker {}", i);
//                         let mut task = scheduler.next_task();
//                         while task.is_some() {
//                             debug!(target: "scalaris::pevm", "try execute next task {:?}", &task);
//                             task = match task.unwrap() {
//                                 Task::Execution(tx_version) => self.try_execute(
//                                     &evm_wapper,
//                                     &scheduler,
//                                     &mut abort_reason,
//                                     tx_version,
//                                 ),
//                                 Task::Validation(tx_version) => {
//                                     try_validate(&mv_memory, &scheduler, &tx_version)
//                                 }
//                             };
//                             debug!(target: "scalaris::pevm", "Task after execute {:?}", &task);
//                             // TODO: Have different functions or an enum for the caller to choose
//                             // the handling behaviour when a transaction's EVM execution fails.
//                             // Parallel block builders would like to exclude such transaction,
//                             // verifiers may want to exit early to save CPU cycles, while testers
//                             // may want to collect all execution results. We are exiting early as
//                             // the default behaviour for now.
//                             if abort_reason.get().is_some() {
//                                 break;
//                             }

//                             if task.is_none() {
//                                 task = scheduler.next_task();
//                             }
//                         }
//                     });
//                 });
//             }
//         }

//         if let Some(abort_reason) = abort_reason.take() {
//             match abort_reason {
//                 AbortReason::FallbackToSequential => {
//                     self.dropper.drop((mv_memory, scheduler, Vec::new()));
//                     return self.sequential_transition(block, evm, system_caller);
//                 }
//                 AbortReason::ExecutionError(err) => {
//                     self.dropper.drop((mv_memory, scheduler, txs));
//                     return Err(BlockExecutionError::Internal(InternalBlockExecutionError::msg(
//                         format!("{err:?}"),
//                     )));
//                 }
//             }
//         }

//         let mut fully_evaluated_results = Vec::with_capacity(block_size);
//         let mut cumulative_gas_used: u128 = 0;
//         for i in 0..block_size {
//             let mut execution_result = index_mutex!(self.execution_results, i).take().unwrap();
//             cumulative_gas_used += execution_result.receipt.cumulative_gas_used as u128;
//             execution_result.receipt.cumulative_gas_used = cumulative_gas_used as u64;
//             fully_evaluated_results.push(execution_result);
//         }

//         // We fully evaluate (the balance and nonce of) the beneficiary account
//         // and raw transfer recipients that may have been atomically updated.
//         for address in mv_memory.consume_lazy_addresses() {
//             let location_hash = self.hasher.hash_one(MemoryLocation::Basic(address));
//             if let Some(write_history) = mv_memory.data.get(&location_hash) {
//                 let mut balance = U256::ZERO;
//                 let mut nonce = 0;
//                 // Read from storage if the first multi-version entry is not an absolute value.
//                 if !matches!(
//                     write_history.first_key_value(),
//                     Some((_, MemoryEntry::Data(_, MemoryValue::Basic(_))))
//                 ) {
//                     if let Ok(Some(account)) = storage.basic(&address) {
//                         balance = account.balance;
//                         nonce = account.nonce;
//                     }
//                 }
//                 // Accounts that take implicit writes like the beneficiary account can be contract!
//                 let code_hash = match storage.code_hash(&address) {
//                     Ok(code_hash) => code_hash,
//                     Err(err) => {
//                         return Err(BlockExecutionError::Internal(
//                             InternalBlockExecutionError::msg(format!("{err:?}")),
//                         ))
//                     }
//                 };
//                 let code = if let Some(code_hash) = &code_hash {
//                     match storage.code_by_hash(code_hash) {
//                         Ok(code) => code,
//                         Err(err) => {
//                             return Err(BlockExecutionError::Internal(
//                                 InternalBlockExecutionError::msg(format!("{err:?}")),
//                             ))
//                         }
//                     }
//                 } else {
//                     None
//                 };

//                 for (tx_idx, memory_entry) in write_history.iter() {
//                     let (tx, _) = unsafe { txs.get_unchecked(*tx_idx) };
//                     match memory_entry {
//                         MemoryEntry::Data(_, MemoryValue::Basic(info)) => {
//                             // We fall back to sequential execution when reading a self-destructed account,
//                             // so an empty account here would be a bug
//                             debug_assert!(!(info.balance.is_zero() && info.nonce == 0));
//                             balance = info.balance;
//                             nonce = info.nonce;
//                         }
//                         MemoryEntry::Data(_, MemoryValue::LazyRecipient(addition)) => {
//                             balance += addition;
//                         }
//                         MemoryEntry::Data(_, MemoryValue::LazySender(addition)) => {
//                             // We must re-do extra sender balance checks as we mock
//                             // the max value in [Vm] during execution. Ideally we
//                             // can turn off these redundant checks in revm.
//                             // TODO: Guard against overflows & underflows
//                             // Ideally we would share these calculations with revm
//                             // (using their utility functions).
//                             let mut max_fee = U256::from(tx.gas_limit) * tx.gas_price + tx.value;
//                             if let Some(blob_fee) = tx.max_fee_per_blob_gas {
//                                 max_fee +=
//                                     U256::from(tx.get_total_blob_gas()) * U256::from(blob_fee);
//                             }
//                             if balance < max_fee {
//                                 return Err(BlockExecutionError::Internal(
//                                     InternalBlockExecutionError::msg(format!(
//                                         "Transaction(LackOfFundForMaxFee)"
//                                     )),
//                                 ));
//                             }
//                             balance -= addition;
//                             // End of overflow TODO

//                             nonce += 1;
//                         }
//                         // TODO: Better error handling
//                         _ => unreachable!(),
//                     }
//                     // Assert that evaluated nonce is correct when address is caller.
//                     debug_assert!(
//                         tx.caller != address || tx.nonce.map_or(true, |n| n + 1 == nonce)
//                     );

//                     // SAFETY: The multi-version data structure should not leak an index over block size.
//                     let tx_result = unsafe { fully_evaluated_results.get_unchecked_mut(*tx_idx) };
//                     let account = tx_result.state.entry(address).or_default();
//                     // TODO: Deduplicate this logic with [PevmTxExecutionResult::from_revm]
//                     if chain.is_eip_161_enabled(evm.spec_id())
//                         && code_hash.is_none()
//                         && nonce == 0
//                         && balance == U256::ZERO
//                     {
//                         *account = None;
//                     } else if let Some(account) = account {
//                         // Explicit write: only overwrite the account info in case there are storage changes
//                         // Code cannot change midblock here as we're falling back to sequential execution
//                         // on reading a self-destructed contract.
//                         account.balance = balance;
//                         account.nonce = nonce;
//                     } else {
//                         // Implicit write: e.g. gas payments to the beneficiary account,
//                         // which doesn't have explicit writes in [tx_result.state]
//                         *account = Some(EvmAccount {
//                             balance,
//                             nonce,
//                             code_hash,
//                             code: code.clone(),
//                             storage: AHashMap::default(),
//                         });
//                     }
//                 }
//             }
//         }

//         self.dropper.drop((mv_memory, scheduler, txs));
//         let receipts = fully_evaluated_results
//             .into_iter()
//             .map(|PevmTxExecutionResult { receipt, state }| {
//                 info!(target: "scalaris::pevm", "state: {:?}", state);
//                 receipt
//             })
//             .collect();
//         let requests = if self.chain_spec.is_prague_active_at_timestamp(block.timestamp) {
//             // Collect all EIP-6110 deposits
//             let deposit_requests =
//                 crate::eip6110::parse_deposits_from_receipts(&self.chain_spec, &receipts)?;

//             let post_execution_requests = system_caller.apply_post_execution_changes(&mut evm)?;

//             [deposit_requests, post_execution_requests].concat()
//         } else {
//             vec![]
//         };

//         Ok(EthExecuteOutput { receipts, requests, gas_used: cumulative_gas_used as u64 })
//     }
//     fn sequential_transition<Ext, DB, F>(
//         &self,
//         block: &BlockWithSenders,
//         mut evm: Evm<'_, Ext, &mut State<DB>>,
//         mut system_caller: SystemCaller<'_, EvmConfig, &Arc<ChainSpec>, F>,
//     ) -> Result<EthExecuteOutput, BlockExecutionError>
//     where
//         Ext: ParallelEvmContextTrait,
//         DB: Database,
//         DB::Error: Into<ProviderError> + Display,
//         F: OnStateHook,
//     {
//         // execute transactions
//         let mut cumulative_gas_used = 0;
//         let mut receipts = Vec::with_capacity(block.body.transactions.len());
//         for (sender, transaction) in block.transactions_with_sender() {
//             let block_available_gas = block.header.gas_limit - cumulative_gas_used;
//             if transaction.gas_limit() > block_available_gas {
//                 return Err(BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
//                     transaction_gas_limit: transaction.gas_limit(),
//                     block_available_gas,
//                 }
//                 .into());
//             }
//             self.evm_config.fill_tx_env(evm.tx_mut(), transaction, *sender);
//             // Execute transaction.
//             let ResultAndState { result, state } = evm.transact().map_err(move |err| {
//                 let new_err = err.map_db_err(|e| e.into());
//                 // Ensure hash is calculated for error log, if not already done
//                 BlockValidationError::EVM {
//                     hash: transaction.recalculate_hash(),
//                     error: Box::new(new_err),
//                 }
//             })?;
//             evm.db_mut().commit(state);

//             // append gas used
//             cumulative_gas_used += result.gas_used();

//             // Push transaction changeset and calculate header bloom filter for receipt.
//             receipts.push(
//                 #[allow(clippy::needless_update)] // side-effect of optimism fields
//                 Receipt {
//                     tx_type: transaction.tx_type(),
//                     // Success flag was added in `EIP-658: Embedding transaction status code in
//                     // receipts`.
//                     success: result.is_success(),
//                     cumulative_gas_used: cumulative_gas_used as u64,
//                     // convert to reth log
//                     logs: result.into_logs(),
//                     ..Default::default()
//                 },
//             );
//         }

//         let requests = if self.chain_spec.is_prague_active_at_timestamp(block.timestamp) {
//             // Collect all EIP-6110 deposits
//             let deposit_requests =
//                 crate::eip6110::parse_deposits_from_receipts(&self.chain_spec, &receipts)?;

//             let post_execution_requests = system_caller.apply_post_execution_changes(&mut evm)?; // Collect all EIP-7685 requests
//                                                                                                  // Collect all EIP-7685 requests
//             [deposit_requests, post_execution_requests].concat()
//         } else {
//             vec![]
//         };

//         Ok(EthExecuteOutput { receipts, requests, gas_used: cumulative_gas_used as u64 })
//     }
//     fn try_execute<'a, S: Storage + 'a, C: PevmChain + 'a>(
//         &self,
//         vm: &EvmWrapper<'a, S, C>,
//         scheduler: &Scheduler,
//         abort_reason: &mut OnceLock<AbortReason>,
//         tx_version: TxVersion,
//     ) -> Option<Task> {
//         loop {
//             return match vm.execute(&tx_version) {
//                 Err(VmExecutionError::Retry) => {
//                     if abort_reason.get().is_none() {
//                         continue;
//                     }
//                     None
//                 }
//                 Err(VmExecutionError::FallbackToSequential) => {
//                     scheduler.abort();
//                     abort_reason.get_or_init(|| AbortReason::FallbackToSequential);
//                     None
//                 }
//                 Err(VmExecutionError::Blocking(blocking_tx_idx)) => {
//                     if !scheduler.add_dependency(tx_version.tx_idx, blocking_tx_idx)
//                         && abort_reason.get().is_none()
//                     {
//                         // Retry the execution immediately if the blocking transaction was
//                         // re-executed by the time we can add it as a dependency.
//                         continue;
//                     }
//                     None
//                 }
//                 Err(VmExecutionError::ExecutionError(err)) => {
//                     scheduler.abort();
//                     abort_reason.get_or_init(|| AbortReason::ExecutionError(err));
//                     None
//                 }
//                 Ok(VmExecutionResult { execution_result, flags }) => {
//                     debug!(target: "scalaris::pevm", "Finished execution with result {:?}", execution_result);
//                     *index_mutex!(self.execution_results, tx_version.tx_idx) =
//                         Some(execution_result);
//                     let next_task = scheduler.finish_execution(tx_version, flags);
//                     debug!(target: "scalaris::pevm", "Finished execution with next task {:?}", &next_task);
//                     next_task
//                 }
//             };
//         }
//     }
// }

// async fn try_validate(
//     mv_memory: &MvMemory,
//     scheduler: &Scheduler,
//     tx_version: &TxVersion,
// ) -> Option<Task> {
//     let read_set_valid = mv_memory.validate_read_locations(tx_version.tx_idx).await;
//     let aborted = !read_set_valid && scheduler.try_validation_abort(tx_version);
//     if aborted {
//         mv_memory.convert_writes_to_estimates(tx_version.tx_idx).await;
//     }
//     scheduler.finish_validation(tx_version, aborted)
// }
