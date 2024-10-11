use reth_primitives::{Receipt, TxType};
// use alloy_consensus::Receipt;
use revm_primitives::{Address, EVMError, ResultAndState, SpecId};
use std::collections::HashMap;

use crate::executor::parallel::{
    chain::PevmChain,
    types::{BuildSuffixHasher, EvmAccount, FinishExecFlags, TxIdx},
};

#[derive(Debug)]
pub(crate) enum VmExecutionError {
    Retry,
    FallbackToSequential,
    Blocking(TxIdx),
    ExecutionError(ExecutionError),
}

/// Errors when reading a memory location.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ReadError {
    /// Cannot read memory location from storage.
    StorageError(String),
    /// This memory location has been written by a lower transaction.
    Blocking(TxIdx),
    /// There has been an inconsistent read like reading the same
    /// location from storage in the first call but from [VmMemory] in
    /// the next.
    InconsistentRead,
    /// Found an invalid nonce, like the first transaction of a sender
    /// not having a (+1) nonce from storage.
    InvalidNonce(TxIdx),
    /// Read a self-destructed account that is very hard to handle, as
    /// there is no performant way to mark all storage slots as cleared.
    SelfDestructedAccount,
    /// The stored memory value type doesn't match its location type.
    /// TODO: Handle this at the type level?
    InvalidMemoryValueType,
}

impl From<ReadError> for VmExecutionError {
    fn from(err: ReadError) -> Self {
        match err {
            ReadError::InconsistentRead => VmExecutionError::Retry,
            ReadError::SelfDestructedAccount => VmExecutionError::FallbackToSequential,
            ReadError::Blocking(tx_idx) => VmExecutionError::Blocking(tx_idx),
            _ => VmExecutionError::ExecutionError(EVMError::Database(err)),
        }
    }
}
#[derive(Debug)]
pub(crate) struct VmExecutionResult {
    pub(crate) execution_result: PevmTxExecutionResult,
    pub(crate) flags: FinishExecFlags,
}

/// The execution error from the underlying EVM executor.
// Will there be DB errors outside of read?
pub(crate) type ExecutionError = EVMError<ReadError>;

/// Represents the state transitions of the EVM accounts after execution.
/// If the value is [None], it indicates that the account is marked for removal.
/// If the value is [Some(new_state)], it indicates that the account has become [new_state].
pub(crate) type EvmStateTransitions = HashMap<Address, Option<EvmAccount>, BuildSuffixHasher>;

/// Execution result of a transaction
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PevmTxExecutionResult {
    /// Receipt of execution
    // TODO: Consider promoting to [ReceiptEnvelope] if there is high demand
    pub receipt: Receipt,
    /// State that got updated
    pub state: EvmStateTransitions,
}

impl PevmTxExecutionResult {
    /// Construct a Pevm execution result from a raw Revm result.
    /// Note that [cumulative_gas_used] is preset to the gas used of this transaction.
    /// It should be post-processed with the remaining transactions in the block.
    pub(crate) fn from_revm<C: PevmChain>(
        chain: &C,
        spec_id: SpecId,
        ResultAndState { result, state }: ResultAndState,
        tx_type: &TxType,
    ) -> Self {
        Self {
            receipt: Receipt {
                //status: result.is_success().into(),
                tx_type: tx_type.clone(),
                success: result.is_success(),
                cumulative_gas_used: result.gas_used(),
                logs: result.into_logs(),
                #[cfg(feature = "optimism")]
                deposit_nonce: None,
                #[cfg(feature = "optimism")]
                deposit_receipt_version: None,
            },
            state: state
                .into_iter()
                .filter(|(_, account)| account.is_touched())
                .map(|(address, account)| {
                    if account.is_selfdestructed()
                        || account.is_empty() && chain.is_eip_161_enabled(spec_id)
                    {
                        (address, None)
                    } else {
                        (address, Some(EvmAccount::from(account)))
                    }
                })
                .collect(),
        }
    }
}
