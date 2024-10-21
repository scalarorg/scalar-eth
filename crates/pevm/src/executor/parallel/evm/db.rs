use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use ahash::HashMapExt;
use arc_swap::{ArcSwap, ArcSwapOption};
use revm::Database;
use revm_primitives::{AccountInfo, Address, Bytecode, TxEnv, TxKind, B256, KECCAK_EMPTY, U256};
use smallvec::SmallVec;

use crate::executor::parallel::{
    memory::MvMemory,
    storage::Storage,
    types::{
        AccountBasic, BuildIdentityHasher, MemoryEntry, MemoryLocation, MemoryLocationHash,
        MemoryValue, ReadOrigin, ReadOrigins, ReadSet, TxIdx, TxVersion,
    },
};

use super::ReadError;

// A database interface that intercepts reads while executing a specific
// transaction with Revm. It provides values from the multi-version data
// structure & storage, and tracks the read set of the current execution.
pub(crate) struct VmDb<S: Storage> {
    mv_memory: Arc<ArcSwapOption<MvMemory>>,
    storage: Arc<S>,
    hasher: Arc<ahash::RandomState>,
    tx_idx: Option<TxIdx>,
    tx: Option<TxEnv>,
    from_hash: Option<MemoryLocationHash>,
    to_hash: Option<MemoryLocationHash>,
    to_code_hash: Option<B256>,
    // Indicates if we lazy update this transaction.
    // Only applied to raw transfers' senders & recipients at the moment.
    is_lazy: bool,
    read_set: ArcSwap<Mutex<ReadSet>>,
    // TODO: Clearer type for [AccountBasic] plus code hash
    read_accounts: HashMap<MemoryLocationHash, (AccountBasic, Option<B256>), BuildIdentityHasher>,
}

impl<S: Storage> VmDb<S> {
    pub(super) fn new(
        mv_memory: Arc<ArcSwapOption<MvMemory>>,
        storage: Arc<S>,
        hasher: Arc<ahash::RandomState>,
        // from_hash: MemoryLocationHash,
        // to_hash: Option<MemoryLocationHash>,
    ) -> Self {
        let db = Self {
            mv_memory,
            storage,
            hasher,
            tx_idx: None,
            tx: None,
            from_hash: None,
            to_hash: None,
            to_code_hash: None,
            is_lazy: false,
            // Unless it is a raw transfer that is lazy updated, we'll
            // read at least from the sender and recipient accounts.
            read_set: ArcSwap::new(Arc::new(Mutex::new(ReadSet::with_capacity(2)))),
            read_accounts: HashMap::with_capacity_and_hasher(2, BuildIdentityHasher::default()),
        };
        // We only lazy update raw transfers that already have the sender
        // or recipient in [MvMemory] since sequentially evaluating memory
        // locations with only one entry is much costlier than fully
        // evaluating it concurrently.
        // TODO: Only lazy update in block syncing mode, not for block
        // building.
        // if let TxKind::Call(to) = tx.transact_to {
        //     db.to_code_hash = db.get_code_hash(to)?;
        //     db.is_lazy = db.to_code_hash.is_none()
        //         && (self.mv_memory.data.contains_key(&from_hash)
        //             || self.mv_memory.data.contains_key(&to_hash.unwrap()));
        // }
        db
    }

    fn hash_basic(&self, address: &Address) -> MemoryLocationHash {
        if Some(address) == self.tx.as_ref().map(|tx| &tx.caller) && self.from_hash.is_some() {
            return self.from_hash.unwrap();
        }
        if let Some(TxKind::Call(to)) = self.tx.as_ref().map(|tx| &tx.transact_to) {
            if to == address {
                return self.to_hash.unwrap();
            }
        }
        self.hasher.hash_one(MemoryLocation::Basic(*address))
    }

    // Push a new read origin. Return an error when there's already
    // an origin but doesn't match the new one to force re-execution.
    fn push_origin(read_origins: &mut ReadOrigins, origin: ReadOrigin) -> Result<(), ReadError> {
        if let Some(prev_origin) = read_origins.last() {
            if prev_origin != &origin {
                return Err(ReadError::InconsistentRead);
            }
        } else {
            read_origins.push(origin);
        }
        Ok(())
    }

    fn get_code_hash(&mut self, address: Address) -> Result<Option<B256>, ReadError> {
        let location_hash = self.hasher.hash_one(MemoryLocation::CodeHash(address));
        let read_set = self.read_set.load();
        let mut read_set =
            read_set.lock().map_err(|err| ReadError::StorageError(err.to_string()))?;

        let read_origins = read_set.entry(location_hash).or_default();

        // Try to read the latest code hash in [MvMemory]
        // TODO: Memoize read locations (expected to be small) here in [Vm] to avoid
        // contention in [MvMemory]
        let mv_memory = self.mv_memory.load();
        if let Some(written_transactions) =
            mv_memory.as_ref().and_then(|memory| memory.data.get(&location_hash))
        {
            if let Some((tx_idx, MemoryEntry::Data(tx_incarnation, value))) =
                written_transactions.range(..self.tx_idx.clone().unwrap_or(0)).next_back()
            {
                match value {
                    MemoryValue::SelfDestructed => {
                        return Err(ReadError::SelfDestructedAccount);
                    }
                    MemoryValue::CodeHash(code_hash) => {
                        Self::push_origin(
                            read_origins,
                            ReadOrigin::MvMemory(TxVersion {
                                tx_idx: *tx_idx,
                                tx_incarnation: *tx_incarnation,
                            }),
                        )?;
                        return Ok(Some(*code_hash));
                    }
                    _ => {}
                }
            }
        };

        // Fallback to storage
        Self::push_origin(read_origins, ReadOrigin::Storage)?;
        self.storage.code_hash(&address).map_err(|err| ReadError::StorageError(err.to_string()))
    }
    fn has_storage(&mut self, address: Address) -> Result<bool, ReadError> {
        self.storage.has_storage(&address).map_err(|err| ReadError::StorageError(err.to_string()))
    }
}

impl<S: Storage> Database for VmDb<S> {
    type Error = ReadError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let location_hash = self.hash_basic(&address);

        // We return a mock for non-contract addresses (for lazy updates) to avoid
        // unnecessarily evaluating its balance here.
        if self.is_lazy {
            if Some(location_hash) == self.from_hash {
                return Ok(Some(AccountInfo {
                    nonce: self.tx.as_ref().and_then(|tx| tx.nonce).unwrap_or(0),
                    balance: U256::MAX,
                    code: None,
                    code_hash: KECCAK_EMPTY,
                }));
            } else if Some(location_hash) == self.to_hash {
                return Ok(None);
            }
        }

        let read_set = self.read_set.load();
        let mut read_set =
            read_set.lock().map_err(|err| ReadError::StorageError(err.to_string()))?;
        let read_origins = read_set.entry(location_hash).or_default();
        let has_prev_origins = !read_origins.is_empty();
        // We accumulate new origins to either:
        // - match with the previous origins to check consistency
        // - register origins on the first read
        let mut new_origins = SmallVec::new();

        let mut final_account = None;
        let mut balance_addition = U256::ZERO;
        // The sign of [balance_addition] since it can be negative for lazy senders.
        let mut positive_addition = true;
        let mut nonce_addition = 0;

        // Try reading from multi-version data
        let mv_memory = self.mv_memory.load();
        if self.tx_idx.is_some_and(|ind| ind > 0) && mv_memory.is_some() {
            if let Some(written_transactions) = mv_memory.as_ref().unwrap().data.get(&location_hash)
            {
                let mut iter = written_transactions.range(..self.tx_idx.as_ref().unwrap());

                // Fully evaluate lazy updates
                loop {
                    match iter.next_back() {
                        Some((blocking_idx, MemoryEntry::Estimate)) => {
                            return Err(ReadError::Blocking(*blocking_idx))
                        }
                        Some((closest_idx, MemoryEntry::Data(tx_incarnation, value))) => {
                            // About to push a new origin
                            // Inconsistent: new origin will be longer than the previous!
                            if has_prev_origins && read_origins.len() == new_origins.len() {
                                return Err(ReadError::InconsistentRead);
                            }
                            let origin = ReadOrigin::MvMemory(TxVersion {
                                tx_idx: *closest_idx,
                                tx_incarnation: *tx_incarnation,
                            });
                            // Inconsistent: new origin is different from the previous!
                            if has_prev_origins
                                && unsafe { read_origins.get_unchecked(new_origins.len()) }
                                    != &origin
                            {
                                return Err(ReadError::InconsistentRead);
                            }
                            new_origins.push(origin);
                            match value {
                                MemoryValue::Basic(basic) => {
                                    // TODO: Return [SelfDestructedAccount] if [basic] is
                                    // [SelfDestructed]?
                                    // For now we are betting on [code_hash] triggering the
                                    // sequential fallback when we read a self-destructed contract.
                                    final_account = Some(basic.clone());
                                    break;
                                }
                                MemoryValue::LazyRecipient(addition) => {
                                    if positive_addition {
                                        balance_addition += addition;
                                    } else {
                                        positive_addition = *addition >= balance_addition;
                                        balance_addition = balance_addition.abs_diff(*addition);
                                    }
                                }
                                MemoryValue::LazySender(subtraction) => {
                                    if positive_addition {
                                        positive_addition = balance_addition >= *subtraction;
                                        balance_addition = balance_addition.abs_diff(*subtraction);
                                    } else {
                                        balance_addition += subtraction;
                                    }
                                    nonce_addition += 1;
                                }
                                _ => return Err(ReadError::InvalidMemoryValueType),
                            }
                        }
                        None => {
                            break;
                        }
                    }
                }
            }
        }

        // Fall back to storage
        if final_account.is_none() {
            // Populate [Storage] on the first read
            if !has_prev_origins {
                new_origins.push(ReadOrigin::Storage);
            }
            // Inconsistent: previous origin is longer or didn't read
            // from storage for the last origin.
            else if read_origins.len() != new_origins.len() + 1
                || read_origins.last() != Some(&ReadOrigin::Storage)
            {
                return Err(ReadError::InconsistentRead);
            }
            final_account = match self.storage.basic(&address) {
                Ok(Some(basic)) => Some(basic),
                Ok(None) => {
                    if balance_addition > U256::ZERO {
                        Some(AccountBasic::default())
                    } else {
                        None
                    }
                }
                Err(err) => return Err(ReadError::StorageError(err.to_string())),
            };
        }

        // Populate read origins on the first read.
        // Otherwise [read_origins] matches [new_origins] already.
        if !has_prev_origins {
            *read_origins = new_origins;
        }

        if let Some(mut account) = final_account {
            // Check sender nonce
            account.nonce += nonce_addition;
            if Some(location_hash) == self.from_hash
                && self.tx.as_ref().unwrap().nonce.is_some_and(|nonce| nonce != account.nonce)
            {
                if self.tx_idx.is_some_and(|ind| ind > 0) {
                    // TODO: Better retry strategy -- immediately, to the
                    // closest sender tx, to the missing sender tx, etc.
                    return Err(ReadError::Blocking(self.tx_idx.as_ref().unwrap() - 1));
                } else {
                    return Err(ReadError::InvalidNonce(self.tx_idx.unwrap_or(0)));
                }
            }

            // Fully evaluate the account and register it to read cache
            // to later check if they have changed (been written to).
            if positive_addition {
                account.balance += balance_addition;
            } else {
                account.balance -= balance_addition;
            };

            let code_hash = if Some(location_hash) == self.to_hash {
                self.to_code_hash
            } else {
                self.get_code_hash(address)?
            };
            let code = if let Some(code_hash) = &code_hash {
                if let Some(code) =
                    mv_memory.as_ref().and_then(|memory| memory.new_bytecodes.get(code_hash))
                {
                    Some(code.clone())
                } else {
                    match self.storage.code_by_hash(code_hash) {
                        Ok(code) => code.map(Bytecode::from),
                        Err(err) => return Err(ReadError::StorageError(err.to_string())),
                    }
                }
            } else {
                None
            };
            self.read_accounts.insert(location_hash, (account.clone(), code_hash));

            return Ok(Some(AccountInfo {
                balance: account.balance,
                nonce: account.nonce,
                code_hash: code_hash.unwrap_or(KECCAK_EMPTY),
                code,
            }));
        }

        Ok(None)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.storage
            .code_by_hash(&code_hash)
            .map(|code| code.map(Bytecode::from).unwrap_or_default())
            .map_err(|err| ReadError::StorageError(err.to_string()))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let location_hash = self.hasher.hash_one(MemoryLocation::Storage(address, index));

        let read_set = self.read_set.load();
        let mut read_set =
            read_set.lock().map_err(|err| ReadError::StorageError(err.to_string()))?;
        let read_origins = read_set.entry(location_hash).or_default();

        // Try reading from multi-version data
        let mv_memory = self.mv_memory.load();
        if self.tx_idx.is_some_and(|ind| ind > 0) && mv_memory.is_some() {
            if let Some(written_transactions) =
                mv_memory.as_ref().and_then(|memory| memory.data.get(&location_hash))
            {
                if let Some((closest_idx, entry)) =
                    written_transactions.range(..self.tx_idx.as_ref().unwrap()).next_back()
                {
                    match entry {
                        MemoryEntry::Data(tx_incarnation, MemoryValue::Storage(value)) => {
                            Self::push_origin(
                                read_origins,
                                ReadOrigin::MvMemory(TxVersion {
                                    tx_idx: *closest_idx,
                                    tx_incarnation: *tx_incarnation,
                                }),
                            )?;
                            return Ok(*value);
                        }
                        MemoryEntry::Estimate => return Err(ReadError::Blocking(*closest_idx)),
                        _ => return Err(ReadError::InvalidMemoryValueType),
                    }
                }
            }
        }

        // Fall back to storage
        Self::push_origin(read_origins, ReadOrigin::Storage)?;
        self.storage
            .storage(&address, &index)
            .map_err(|err| ReadError::StorageError(err.to_string()))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.storage.block_hash(&number).map_err(|err| ReadError::StorageError(err.to_string()))
    }
}

pub(crate) trait DBTracking {
    fn is_lazy(&self) -> bool;
    fn get_read_set(&self) -> Arc<Mutex<ReadSet>>;
    fn get_read_account(
        &self,
        location_hash: &MemoryLocationHash,
    ) -> Option<&(AccountBasic, Option<B256>)>;
}

impl<S: Storage> DBTracking for VmDb<S> {
    fn is_lazy(&self) -> bool {
        self.is_lazy
    }
    fn get_read_set(&self) -> Arc<Mutex<ReadSet>> {
        let len = self.read_set.load().lock().unwrap().len();
        self.read_set.swap(Arc::new(Mutex::new(ReadSet::with_capacity(len))))
    }
    fn get_read_account(
        &self,
        location_hash: &MemoryLocationHash,
    ) -> Option<&(AccountBasic, Option<B256>)> {
        self.read_accounts.get(location_hash)
    }
}
