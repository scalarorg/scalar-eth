use std::fmt::Debug;

use alloy_primitives::{keccak256, Address, B256, U256};

use super::Storage;
use super::{BlockHashes, Bytecodes, ChainState, EvmCode};
use crate::executor::parallel::types::{
    AccountBasic, BuildIdentityHasher, BuildSuffixHasher, EvmAccount,
};
/// A storage that stores chain data in memory.
#[derive(Debug, Default, Clone)]
pub struct InMemoryStorage<'a> {
    accounts: ChainState,
    bytecodes: Option<&'a Bytecodes>,
    block_hashes: BlockHashes,
}

impl<'a> InMemoryStorage<'a> {
    /// Construct a new [InMemoryStorage]
    pub(crate) fn new(
        accounts: impl IntoIterator<Item = (Address, EvmAccount)>,
        bytecodes: Option<&'a Bytecodes>,
        block_hashes: impl IntoIterator<Item = (u64, B256)>,
    ) -> Self {
        InMemoryStorage {
            accounts: accounts.into_iter().collect(),
            bytecodes,
            block_hashes: block_hashes.into_iter().collect(),
        }
    }
    pub(crate) fn set_block_hash(&mut self, number: u64, hash: B256) {
        self.block_hashes.insert(number, hash);
    }
    pub(crate) fn insert_address(&mut self, address: Address, account: EvmAccount) {
        self.accounts.insert(address, account);
    }
}

impl<'a> Storage for InMemoryStorage<'a> {
    // TODO: More proper error handling
    type Error = u8;

    fn basic(&self, address: &Address) -> Result<Option<AccountBasic>, Self::Error> {
        Ok(self
            .accounts
            .get(address)
            .map(|account| AccountBasic { balance: account.balance, nonce: account.nonce }))
    }

    fn code_hash(&self, address: &Address) -> Result<Option<B256>, Self::Error> {
        Ok(self.accounts.get(address).and_then(|account| account.code_hash))
    }

    fn code_by_hash(&self, code_hash: &B256) -> Result<Option<EvmCode>, Self::Error> {
        Ok(match self.bytecodes {
            Some(bytecodes) => bytecodes.get(code_hash).cloned(),
            None => None,
        })
    }

    fn has_storage(&self, address: &Address) -> Result<bool, Self::Error> {
        Ok(self.accounts.get(address).is_some_and(|account| !account.storage.is_empty()))
    }

    fn storage(&self, address: &Address, index: &U256) -> Result<U256, Self::Error> {
        Ok(self
            .accounts
            .get(address)
            .and_then(|account| account.storage.get(index))
            .cloned()
            .unwrap_or_default())
    }

    fn block_hash(&self, number: &u64) -> Result<B256, Self::Error> {
        Ok(self
            .block_hashes
            .get(number)
            .cloned()
            // Matching REVM's [EmptyDB] for now
            .unwrap_or_else(|| keccak256(number.to_string().as_bytes())))
    }
}
