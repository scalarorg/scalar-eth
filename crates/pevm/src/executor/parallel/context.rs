use super::{storage::InMemoryStorage, types::EvmAccount};
use alloy_primitives::Address;
use revm_primitives::B256;

/// Parallel EVM external context trait
/// For Manipulation external context in EVMWrapper
pub trait ParallelEvmContextTrait {
    // fn storage(&self) -> &InMemoryStorage<'_>;
    fn insert_address(&mut self, address: Address, account: EvmAccount);
    fn set_block_hash(&mut self, number: u64, hash: B256);
}
/// Keep inmemory storage for parallel evm context,
/// This storage is fist lazy initialized with genesis state,
/// then update after each block execution.
/// This context must be light weight to be cloned frequently.
#[derive(Default, Debug, Clone)]
pub struct ParallelEvmContext {
    storage: InMemoryStorage<'static>,
}
impl ParallelEvmContext {
    pub(crate) fn new(storage: InMemoryStorage<'static>) -> Self {
        ParallelEvmContext { storage }
    }
}

impl ParallelEvmContextTrait for ParallelEvmContext {
    // fn storage(&self) -> &InMemoryStorage<'_> {
    //     &self.storage
    // }
    fn insert_address(&mut self, address: Address, account: EvmAccount) {
        self.storage.insert_address(address, account);
    }
    fn set_block_hash(&mut self, number: u64, hash: B256) {
        self.storage.set_block_hash(number, hash);
    }
}
