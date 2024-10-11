use ahash::AHashMap;
use alloy_primitives::{Address, Bytes, B256, U256};
use bitflags::bitflags;
use bitvec::vec::BitVec;
use reth_chainspec::Head;
use reth_evm::ConfigureEvm;
use reth_primitives::Header;
use revm::{
    interpreter::analysis::to_analysed,
    primitives::{Account, AccountInfo, Bytecode, JumpTable, KECCAK_EMPTY},
    DatabaseRef,
};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::hash::{BuildHasherDefault, Hasher};
use std::{collections::HashMap, sync::Arc};

use super::ParallelEvmContext;

/// We use the last 8 bytes of an existing hash like address
/// or code hash instead of rehashing it.
// TODO: Make sure this is acceptable for production
#[derive(Debug, Default)]
pub struct SuffixHasher(u64);
impl Hasher for SuffixHasher {
    fn write(&mut self, bytes: &[u8]) {
        let mut suffix = [0u8; 8];
        suffix.copy_from_slice(&bytes[bytes.len() - 8..]);
        self.0 = u64::from_be_bytes(suffix);
    }
    fn finish(&self) -> u64 {
        self.0
    }
}
/// Build a suffix hasher
pub type BuildSuffixHasher = BuildHasherDefault<SuffixHasher>;

/// This is primarily used for memory location hash, but can also be used for
/// transaction indexes, etc.
#[derive(Debug, Default)]
pub struct IdentityHasher(u64);
impl Hasher for IdentityHasher {
    fn write_u64(&mut self, id: u64) {
        self.0 = id;
    }
    fn write_usize(&mut self, id: usize) {
        self.0 = id as u64;
    }
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {
        unreachable!()
    }
}

/// Build an identity hasher
pub type BuildIdentityHasher = BuildHasherDefault<IdentityHasher>;

/// Basic information of an account
// TODO: Reuse something sane from Alloy?
#[derive(Debug, Clone, PartialEq)]
pub struct AccountBasic {
    /// The balance of the account.
    pub balance: U256,
    /// The nonce of the account.
    pub nonce: u64,
}

impl Default for AccountBasic {
    fn default() -> Self {
        Self { balance: U256::ZERO, nonce: 0 }
    }
}

// TODO: Port EVM types to [primitives.rs] to focus solely
// on the [Storage] interface here.

/// An EVM account.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvmAccount {
    /// The account's balance.
    pub balance: U256,
    /// The account's nonce.
    pub nonce: u64,
    /// The optional code hash of the account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_hash: Option<B256>,
    /// The account's optional code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<EvmCode>,
    /// The account's storage.
    pub storage: AHashMap<U256, U256>,
}

impl From<Account> for EvmAccount {
    fn from(account: Account) -> Self {
        let has_code = !account.info.is_empty_code_hash();
        Self {
            balance: account.info.balance,
            nonce: account.info.nonce,
            code_hash: has_code.then_some(account.info.code_hash),
            code: has_code.then(|| account.info.code.unwrap().into()),
            storage: account.storage.into_iter().map(|(k, v)| (k, v.present_value)).collect(),
        }
    }
}
/// pub type EvmCode = Bytecode;
/// EVM Code, currently mapping to REVM's [ByteCode::LegacyAnalyzed].
// TODO: Support raw legacy & EOF
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct EvmCode {
    /// Bytecode with 32 zero bytes padding
    bytecode: Bytes,
    /// Original bytes length
    original_len: usize,
    /// Jump table.
    jump_table: Arc<BitVec<u8>>,
}

impl From<EvmCode> for Bytecode {
    fn from(code: EvmCode) -> Self {
        // TODO: Better error handling.
        // A common trap would be converting a default [EvmCode] into
        // a [Bytecode]. On failure we should fallback to legacy and
        // analyse again.
        unsafe {
            Bytecode::new_analyzed(code.bytecode, code.original_len, JumpTable(code.jump_table))
        }
    }
}

impl From<Bytecode> for EvmCode {
    fn from(code: Bytecode) -> Self {
        match code {
            Bytecode::LegacyRaw(_) => to_analysed(code).into(),
            Bytecode::LegacyAnalyzed(code) => EvmCode {
                bytecode: code.bytecode().clone(),
                original_len: code.original_len(),
                jump_table: code.jump_table().0.clone(),
            },
            Bytecode::Eof(_) => unimplemented!("TODO: Support EOF"),
            Bytecode::Eip7702(_) => unimplemented!("TODO: Support EIP-7702"),
        }
    }
}

// The index of the transaction in the block.
// TODO: Consider downsizing to [u32].
pub(crate) type TxIdx = usize;

// The i-th time a transaction is re-executed, counting from 0.
// TODO: Consider downsizing to [u32].
pub(crate) type TxIncarnation = usize;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum MemoryLocation {
    // TODO: Separate an account's balance and nonce?
    Basic(Address),
    CodeHash(Address),
    Storage(Address, U256),
}

// We only need the full memory location to read from storage.
// We then identify the locations with its hash in the multi-version
// data, write and read sets, which is much faster than rehashing
// on every single lookup & validation.
pub(crate) type MemoryLocationHash = u64;

// TODO: It would be nice if we could tie the different cases of
// memory locations & values at the type level, to prevent lots of
// matches & potentially dangerous mismatch mistakes.
#[derive(Debug, Clone)]
pub(crate) enum MemoryValue {
    Basic(AccountBasic),
    CodeHash(B256),
    Storage(U256),
    // We lazily update the beneficiary balance to avoid continuous
    // dependencies as all transactions read and write to it. We also
    // lazy update the senders & recipients of raw transfers, which are
    // also common (popular CEX addresses, airdrops, etc).
    // We fully evaluate these account states at the end of the block or
    // when there is an explicit read.
    // Explicit balance addition.
    LazyRecipient(U256),
    // Explicit balance subtraction & implicit nonce increment.
    LazySender(U256),
    // The account was self-destructed.
    SelfDestructed,
}

#[derive(Debug)]
pub(crate) enum MemoryEntry {
    Data(TxIncarnation, MemoryValue),
    // When an incarnation is aborted due to a validation failure, the
    // entries in the multi-version data structure corresponding to its
    // write set are replaced with this special ESTIMATE marker.
    // This signifies that the next incarnation is estimated to write to
    // the same memory locations. An incarnation stops and is immediately
    // aborted whenever it reads a value marked as an ESTIMATE written by
    // a lower transaction, instead of potentially wasting a full execution
    // and aborting during validation.
    // The ESTIMATE markers that are not overwritten are removed by the next
    // incarnation.
    Estimate,
}

// - ReadyToExecute(i) --try_incarnate--> Executing(i)
// Non-blocked execution:
//   - Executing(i) --finish_execution--> Executed(i)
//   - Executed(i) --finish_validation--> Validated(i)
//   - Executed/Validated(i) --try_validation_abort--> Aborting(i)
//   - Aborted(i) --finish_validation(w.aborted=true)--> ReadyToExecute(i+1)
// Blocked execution:
//   - Executing(i) --add_dependency--> Aborting(i)
//   - Aborting(i) --resume--> ReadyToExecute(i+1)
#[derive(PartialEq, Debug)]
pub(crate) enum IncarnationStatus {
    ReadyToExecute,
    Executing,
    Executed,
    Validated,
    Aborting,
}

#[derive(PartialEq, Debug)]
pub(crate) struct TxStatus {
    pub(crate) incarnation: TxIncarnation,
    pub(crate) status: IncarnationStatus,
}

// We maintain an in-memory multi-version data structure that stores for
// each memory location the latest value written per transaction, along
// with the associated transaction incarnation. When a transaction reads
// a memory location, it obtains from the multi-version data structure the
// value written to this location by the highest transaction that appears
// before it in the block, along with the associated version. If no previous
// transactions have written to a location, the value would be read from the
// storage state before block execution.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TxVersion {
    pub(crate) tx_idx: TxIdx,
    pub(crate) tx_incarnation: TxIncarnation,
}

// The origin of a memory read. It could be from the live multi-version
// data structure or from storage (chain state before block execution).
#[derive(Debug, PartialEq)]
pub(crate) enum ReadOrigin {
    MvMemory(TxVersion),
    Storage,
}

// Most memory locations only have one read origin. Lazy updated ones like
// the beneficiary balance, raw transfer senders & recipients, etc. have a
// list of lazy updates all the way to the first strict/absolute value.
pub(crate) type ReadOrigins = SmallVec<[ReadOrigin; 1]>;

// For validation: a list of read origins (previous transaction versions)
// for each read memory location.
pub(crate) type ReadSet = HashMap<MemoryLocationHash, ReadOrigins, BuildIdentityHasher>;

// The updates made by this transaction incarnation, which is applied
// to the multi-version data structure at the end of execution.
pub(crate) type WriteSet = Vec<(MemoryLocationHash, MemoryValue)>;

// A scheduled worker task
// TODO: Add more useful work when there are idle workers like near
// the end of block execution, while waiting for a huge blocking
// transaction to resolve, etc.
#[derive(Debug)]
pub(crate) enum Task {
    Execution(TxVersion),
    Validation(TxVersion),
}

bitflags! {
    #[derive(Debug)]
    pub(crate) struct FinishExecFlags: u8 {
        // Do we need to validate from this transaction?
        // The first and lazy transactions don't need validation. Note
        // that this is used to tune the min validation index in the
        // scheduler, meaning a [false] here will still be validated if
        // there was a lower transaction that has broken the preprocessed
        // dependency chain and returned [true]
        const NeedValidation = 0;
        // We need to validate from the next transaction if this execution
        // wrote to a new location.
        const WroteNewLocation = 1;
    }
}
