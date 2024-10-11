use std::{collections::HashMap, fmt::Display};

use alloy_primitives::{Address, B256, U256};
use revm::{
    primitives::{AccountInfo, Bytecode, KECCAK_EMPTY},
    DatabaseRef,
};

use super::types::{AccountBasic, BuildIdentityHasher, BuildSuffixHasher, EvmAccount, EvmCode};

/// Mapping from address to [EvmAccount]
pub(crate) type ChainState = HashMap<Address, EvmAccount, BuildSuffixHasher>;

/// Mapping from code hashes to [EvmCode]s
pub(crate) type Bytecodes = HashMap<B256, EvmCode, BuildSuffixHasher>;

/// Mapping from block numbers to block hashes
pub(crate) type BlockHashes = HashMap<u64, B256, BuildIdentityHasher>;

/// An interface to provide chain state to Pevm for transaction execution.
/// Staying close to the underlying REVM's Database trait while not leaking
/// its primitives to library users (favoring Alloy at the moment).
/// TODO: Better API for third-party integration.
pub trait Storage {
    /// Errors when querying data from storage.
    type Error: Display;

    /// Get basic account information.
    fn basic(&self, address: &Address) -> Result<Option<AccountBasic>, Self::Error>;

    /// Get the code of an account.
    fn code_hash(&self, address: &Address) -> Result<Option<B256>, Self::Error>;

    /// Get account code by its hash.
    fn code_by_hash(&self, code_hash: &B256) -> Result<Option<EvmCode>, Self::Error>;

    /// Get if the account already has storage (to support EIP-7610).
    fn has_storage(&self, address: &Address) -> Result<bool, Self::Error>;

    /// Get storage value of address at index.
    fn storage(&self, address: &Address, index: &U256) -> Result<U256, Self::Error>;

    /// Get block hash by block number.
    fn block_hash(&self, number: &u64) -> Result<B256, Self::Error>;
}

/// A Storage wrapper that implements REVM's [DatabaseRef] for ease of
/// integration.
#[derive(Debug)]
pub struct StorageWrapper<'a, S: Storage>(pub &'a S);

impl<'a, S: Storage> DatabaseRef for StorageWrapper<'a, S> {
    type Error = S::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(if let Some(basic) = self.0.basic(&address)? {
            let code_hash = self.0.code_hash(&address)?;
            let code = if let Some(code_hash) = &code_hash {
                self.0.code_by_hash(code_hash)?.map(Bytecode::from)
            } else {
                None
            };
            Some(AccountInfo {
                balance: basic.balance,
                nonce: basic.nonce,
                code_hash: code_hash.unwrap_or(KECCAK_EMPTY),
                code,
            })
        } else {
            None
        })
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.0.code_by_hash(&code_hash).map(|code| code.map(Bytecode::from).unwrap_or_default())
    }

    // fn has_storage_ref(&self, address: Address) -> Result<bool, Self::Error> {
    //     self.0.has_storage(&address)
    // }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.0.storage(&address, &index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.0.block_hash(&number)
    }
}

mod in_memory;
pub(crate) use in_memory::InMemoryStorage;
mod rpc;
pub(crate) use rpc::RpcStorage;
