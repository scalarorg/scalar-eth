use crate::executor::parallel::{
    chain::{PevmChain, RewardPolicy},
    memory::MvMemory,
    storage::Storage,
    types::{
        AccountBasic, FinishExecFlags, MemoryLocation, MemoryLocationHash, MemoryValue, TxVersion,
        WriteSet,
    },
};
use reth_primitives::TxType;
use revm::{Context, Database, Evm, EvmContext};
use revm_primitives::{
    Address, BlockEnv, CfgEnv, EVMError, Env, InvalidTransaction, SpecId, TxEnv, U256,
};
use smallvec::{smallvec, SmallVec};

use super::{PevmTxExecutionResult, ReadError, VmDb, VmExecutionError, VmExecutionResult};

pub(crate) struct EvmWrapper<'a, S: Storage, C: PevmChain> {
    pub(super) hasher: &'a ahash::RandomState,
    pub(super) storage: &'a S,
    pub(super) mv_memory: &'a MvMemory,
    chain: &'a C,
    block_env: &'a BlockEnv,
    txs: &'a [(TxEnv, TxType)],
    spec_id: SpecId,
    beneficiary_location_hash: MemoryLocationHash,
    reward_policy: RewardPolicy,
}

impl<'a, S: Storage, C: PevmChain> EvmWrapper<'a, S, C> {
    pub(crate) fn new(
        hasher: &'a ahash::RandomState,
        storage: &'a S,
        mv_memory: &'a MvMemory,
        chain: &'a C,
        block_env: &'a BlockEnv,
        txs: &'a [(TxEnv, TxType)],
        spec_id: SpecId,
    ) -> Self {
        Self {
            hasher,
            storage,
            mv_memory,
            chain,
            block_env,
            txs,
            spec_id,
            beneficiary_location_hash: hasher.hash_one(MemoryLocation::Basic(block_env.coinbase)),
            reward_policy: chain.get_reward_policy(hasher),
        }
    }

    #[inline(always)]
    pub(super) fn hash_basic(&self, address: Address) -> MemoryLocationHash {
        self.hasher.hash_one(MemoryLocation::Basic(address))
    }

    // Execute a transaction. This can read from memory but cannot modify any state.
    // A successful execution returns:
    //   - A write-set consisting of memory locations and their updated values.
    //   - A read-set consisting of memory locations and their origins.
    //
    // An execution may observe a read dependency on a lower transaction. This happens
    // when the last incarnation of the dependency wrote to a memory location that
    // this transaction reads, but it aborted before the read. In this case, the
    // dependency index is returned via [blocking_tx_idx]. An execution task for this
    // transaction is re-scheduled after the blocking dependency finishes its
    // next incarnation.
    //
    // When a transaction attempts to write a value to a location, the location and
    // value are added to the write set, possibly replacing a pair with a prior value
    // (if it is not the first time the transaction wrote to this location during the
    // execution).
    pub(crate) fn execute(
        &self,
        tx_version: &TxVersion,
    ) -> Result<VmExecutionResult, VmExecutionError> {
        // SAFETY: A correct scheduler would guarantee this index to be inbound.
        let (tx, tx_type) = unsafe { self.txs.get_unchecked(tx_version.tx_idx) };
        let from_hash = self.hash_basic(tx.caller);
        let to_hash = tx.transact_to.to().map(|to| self.hash_basic(*to));

        // Execute
        let mut db = VmDb::new(self, tx_version.tx_idx, tx, from_hash, to_hash)
            .map_err(VmExecutionError::from)?;
        // TODO: Share as much [Evm], [Context], [Handler], etc. among threads as possible
        // as creating them is very expensive.
        let mut evm = build_evm(
            &mut db,
            self.chain,
            self.spec_id,
            self.block_env.clone(),
            Some(tx.clone()),
            false,
        );
        match evm.transact() {
            Ok(result_and_state) => {
                // There are at least three locations most of the time: the sender,
                // the recipient, and the beneficiary accounts.
                let mut write_set = WriteSet::with_capacity(3);
                for (address, account) in result_and_state.state.iter() {
                    if account.is_selfdestructed() {
                        // TODO: Also write [SelfDestructed] to the basic location?
                        // For now we are betting on [code_hash] triggering the sequential
                        // fallback when we read a self-destructed contract.
                        write_set.push((
                            self.hasher.hash_one(MemoryLocation::CodeHash(*address)),
                            MemoryValue::SelfDestructed,
                        ));
                        continue;
                    }

                    if account.is_touched() {
                        let account_location_hash = self.hash_basic(*address);
                        let read_account = evm.db().read_accounts.get(&account_location_hash);

                        let has_code = !account.info.is_empty_code_hash();
                        let is_new_code = has_code
                            && read_account.map_or(true, |(_, code_hash)| code_hash.is_none());

                        // Write new account changes
                        if is_new_code
                            || read_account.is_none()
                            || read_account.is_some_and(|(basic, _)| {
                                basic.nonce != account.info.nonce
                                    || basic.balance != account.info.balance
                            })
                        {
                            if evm.db().is_lazy {
                                if account_location_hash == from_hash {
                                    write_set.push((
                                        account_location_hash,
                                        MemoryValue::LazySender(U256::MAX - account.info.balance),
                                    ));
                                } else if Some(account_location_hash) == to_hash {
                                    write_set.push((
                                        account_location_hash,
                                        MemoryValue::LazyRecipient(tx.value),
                                    ));
                                }
                            }
                            // We don't register empty accounts after [SPURIOUS_DRAGON]
                            // as they are cleared. This can only happen via 2 ways:
                            // 1. Self-destruction which is handled by an if above.
                            // 2. Sending 0 ETH to an empty account, which we treat as a
                            // non-write here. A later read would trace back to storage
                            // and return a [None], i.e., [LoadedAsNotExisting]. Without
                            // this check it would write then read a [Some] default
                            // account, which may yield a wrong gas fee, etc.
                            else if !self.chain.is_eip_161_enabled(self.spec_id)
                                || !account.is_empty()
                            {
                                write_set.push((
                                    account_location_hash,
                                    MemoryValue::Basic(AccountBasic {
                                        balance: account.info.balance,
                                        nonce: account.info.nonce,
                                    }),
                                ));
                            }
                        }

                        // Write new contract
                        if is_new_code {
                            write_set.push((
                                self.hasher.hash_one(MemoryLocation::CodeHash(*address)),
                                MemoryValue::CodeHash(account.info.code_hash),
                            ));
                            self.mv_memory
                                .new_bytecodes
                                .entry(account.info.code_hash)
                                .or_insert_with(|| account.info.code.clone().unwrap());
                        }
                    }

                    // TODO: We should move this changed check to our read set like for account info?
                    for (slot, value) in account.changed_storage_slots() {
                        write_set.push((
                            self.hasher.hash_one(MemoryLocation::Storage(*address, *slot)),
                            MemoryValue::Storage(value.present_value),
                        ));
                    }
                }

                self.apply_rewards(
                    &mut write_set,
                    tx,
                    U256::from(result_and_state.result.gas_used()),
                    #[cfg(feature = "optimism")]
                    &evm.context.evm,
                )?;

                drop(evm); // release db

                if db.is_lazy {
                    self.mv_memory.add_lazy_addresses([tx.caller, *tx.transact_to.to().unwrap()]);
                }

                let mut flags = if tx_version.tx_idx > 0 && !db.is_lazy {
                    FinishExecFlags::NeedValidation
                } else {
                    FinishExecFlags::empty()
                };

                if self.mv_memory.record(tx_version, db.read_set, write_set) {
                    flags |= FinishExecFlags::WroteNewLocation;
                }

                Ok(VmExecutionResult {
                    execution_result: PevmTxExecutionResult::from_revm(
                        self.chain,
                        self.spec_id,
                        result_and_state,
                        tx_type,
                    ),
                    flags,
                })
            }
            Err(EVMError::Database(read_error)) => Err(read_error.into()),
            Err(err) => {
                // Optimistically retry in case some previous internal transactions send
                // more fund to the sender but hasn't been executed yet.
                // TODO: Let users define this behaviour through a mode enum or something.
                // Since this retry is safe for syncing canonical blocks but can deadlock
                // on new or faulty blocks. We can skip the transaction for new blocks and
                // error out after a number of tries for the latter.
                if tx_version.tx_idx > 0
                    && matches!(
                        err,
                        EVMError::Transaction(InvalidTransaction::LackOfFundForMaxFee { .. })
                            | EVMError::Transaction(InvalidTransaction::NonceTooHigh { .. })
                    )
                {
                    Err(VmExecutionError::Blocking(tx_version.tx_idx - 1))
                } else {
                    Err(VmExecutionError::ExecutionError(err))
                }
            }
        }
    }

    // Apply rewards (balance increments) to beneficiary accounts, etc.
    fn apply_rewards<#[cfg(feature = "optimism")] DB: Database>(
        &self,
        write_set: &mut WriteSet,
        tx: &TxEnv,
        gas_used: U256,
        #[cfg(feature = "optimism")] evm_context: &EvmContext<DB>,
    ) -> Result<(), VmExecutionError> {
        let mut gas_price = if let Some(priority_fee) = tx.gas_priority_fee {
            std::cmp::min(tx.gas_price, priority_fee + self.block_env.basefee)
        } else {
            tx.gas_price
        };
        if self.chain.is_eip_1559_enabled(self.spec_id) {
            gas_price = gas_price.saturating_sub(self.block_env.basefee);
        }

        let rewards: SmallVec<[(MemoryLocationHash, U256); 1]> = match self.reward_policy {
            RewardPolicy::Ethereum => {
                smallvec![(self.beneficiary_location_hash, gas_price * gas_used)]
            }
            #[cfg(feature = "optimism")]
            RewardPolicy::Optimism {
                l1_fee_recipient_location_hash,
                base_fee_vault_location_hash,
            } => {
                let is_deposit = tx.optimism.source_hash.is_some();
                if is_deposit {
                    SmallVec::new()
                } else {
                    // TODO: Better error handling
                    // https://github.com/bluealloy/revm/blob/16e1ecb9a71544d9f205a51a22d81e2658202fde/crates/revm/src/optimism/handler_register.rs#L267
                    let Some(enveloped_tx) = &tx.optimism.enveloped_tx else {
                        panic!("[OPTIMISM] Failed to load enveloped transaction.");
                    };
                    let Some(l1_block_info) = &evm_context.l1_block_info else {
                        panic!("[OPTIMISM] Missing l1_block_info.");
                    };
                    let l1_cost = l1_block_info.calculate_tx_l1_cost(enveloped_tx, self.spec_id);

                    smallvec![
                        (self.beneficiary_location_hash, gas_price * gas_used),
                        (l1_fee_recipient_location_hash, l1_cost),
                        (base_fee_vault_location_hash, self.block_env.basefee * gas_used,),
                    ]
                }
            }
        };

        for (recipient, amount) in rewards {
            if let Some((_, value)) =
                write_set.iter_mut().find(|(location, _)| location == &recipient)
            {
                match value {
                    MemoryValue::Basic(basic) => basic.balance += amount,
                    MemoryValue::LazySender(addition) => *addition -= amount,
                    MemoryValue::LazyRecipient(addition) => *addition += amount,
                    _ => return Err(ReadError::InvalidMemoryValueType.into()),
                }
            } else {
                write_set.push((recipient, MemoryValue::LazyRecipient(amount)));
            }
        }

        Ok(())
    }
}

pub(crate) fn build_evm<'a, DB: Database, C: PevmChain>(
    db: DB,
    chain: &C,
    spec_id: SpecId,
    block_env: BlockEnv,
    tx_env: Option<TxEnv>,
    with_reward_beneficiary: bool,
) -> Evm<'a, (), DB> {
    // This is much uglier than the builder interface but can be up to 50% faster!!
    let context = Context {
        evm: EvmContext::new_with_env(
            db,
            Env::boxed(
                CfgEnv::default().with_chain_id(chain.id()),
                block_env,
                tx_env.unwrap_or_default(),
            ),
        ),
        external: (),
    };

    let handler = chain.get_handler(spec_id, with_reward_beneficiary);
    Evm::new(context, handler)
}
