//! Ethereum executor test.

// use super::EthExecutorProvider;
// use alloc::sync::Arc;
// use alloy_primitives::{BlockNumber, U256};
// use core::fmt::Display;
// use reth_chainspec::{ChainSpec, EthereumHardforks, MAINNET};
// use reth_ethereum_consensus::validate_block_post_execution;
// use reth_evm::{
//     execute::{
//         BatchExecutor, BlockExecutionError, BlockExecutionInput, BlockExecutionOutput,
//         BlockExecutorProvider, BlockValidationError, Executor, ProviderError,
//     },
//     ConfigureEvm,
// };
// use reth_execution_types::ExecutionOutcome;
// use reth_primitives::{BlockWithSenders, EthereumHardfork, Header, Receipt, Request};
// use reth_prune_types::PruneModes;
// use reth_revm::{
//     batch::BlockBatchRecord,
//     db::{states::bundle_state::BundleRetention, State},
//     state_change::post_block_balance_increments,
//     Evm,
// };
// use revm_primitives::{
//     db::{Database, DatabaseCommit},
//     BlockEnv, CfgEnvWithHandlerCfg, EnvWithHandlerCfg, ResultAndState,
// };

#[cfg(test)]
mod tests {
    use crate::executor::EthExecutorProvider;
    use crate::EthEvmConfig;
    use alloc::sync::Arc;
    use alloy_primitives::U256;
    // use super::*;
    use alloy_consensus::TxLegacy;
    use alloy_eips::{
        eip2935::{HISTORY_STORAGE_ADDRESS, HISTORY_STORAGE_CODE},
        eip4788::{BEACON_ROOTS_ADDRESS, BEACON_ROOTS_CODE, SYSTEM_ADDRESS},
        eip7002::{WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS, WITHDRAWAL_REQUEST_PREDEPLOY_CODE},
    };
    use alloy_primitives::{b256, fixed_bytes, keccak256, Bytes, TxKind, B256};
    use reth_chainspec::{ChainSpec, ChainSpecBuilder, ForkCondition, MAINNET};
    use reth_evm::execute::{
        BatchExecutor, BlockExecutionOutput, BlockExecutorProvider, BlockValidationError, Executor,
    };
    use reth_primitives::{
        constants::{EMPTY_ROOT_HASH, ETH_TO_WEI},
        public_key_to_address, Account, Block, BlockBody, BlockWithSenders, EthereumHardfork,
        Header, Transaction,
    };
    use reth_revm::{
        database::StateProviderDatabase, test_utils::StateProviderTest, TransitionState,
    };
    use reth_testing_utils::generators::{self, sign_tx_with_key_pair};
    use revm_primitives::{db::Database, BLOCKHASH_SERVE_WINDOW};
    use secp256k1::{Keypair, Secp256k1};
    use std::collections::HashMap;

    fn create_state_provider_with_beacon_root_contract() -> StateProviderTest {
        let mut db = StateProviderTest::default();

        let beacon_root_contract_account = Account {
            balance: U256::ZERO,
            bytecode_hash: Some(keccak256(BEACON_ROOTS_CODE.clone())),
            nonce: 1,
        };

        db.insert_account(
            BEACON_ROOTS_ADDRESS,
            beacon_root_contract_account,
            Some(BEACON_ROOTS_CODE.clone()),
            HashMap::default(),
        );

        db
    }

    fn create_state_provider_with_withdrawal_requests_contract() -> StateProviderTest {
        let mut db = StateProviderTest::default();

        let withdrawal_requests_contract_account = Account {
            nonce: 1,
            balance: U256::ZERO,
            bytecode_hash: Some(keccak256(WITHDRAWAL_REQUEST_PREDEPLOY_CODE.clone())),
        };

        db.insert_account(
            WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
            withdrawal_requests_contract_account,
            Some(WITHDRAWAL_REQUEST_PREDEPLOY_CODE.clone()),
            HashMap::default(),
        );

        db
    }

    fn executor_provider(chain_spec: Arc<ChainSpec>) -> EthExecutorProvider<EthEvmConfig> {
        EthExecutorProvider { evm_config: EthEvmConfig::new(chain_spec.clone()), chain_spec }
    }

    #[test]
    fn eip_4788_non_genesis_call() {
        let mut header =
            Header { timestamp: 1, number: 1, excess_blob_gas: Some(0), ..Header::default() };

        let db = create_state_provider_with_beacon_root_contract();

        let chain_spec = Arc::new(
            ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(1))
                .build(),
        );

        let provider = executor_provider(chain_spec);

        // attempt to execute a block without parent beacon block root, expect err
        let err = provider
            .executor(StateProviderDatabase::new(&db))
            .execute(
                (
                    &BlockWithSenders {
                        block: Block {
                            header: header.clone(),
                            body: BlockBody {
                                transactions: vec![],
                                ommers: vec![],
                                withdrawals: None,
                                requests: None,
                            },
                        },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .expect_err(
                "Executing cancun block without parent beacon block root field should fail",
            );

        assert_eq!(
            err.as_validation().unwrap().clone(),
            BlockValidationError::MissingParentBeaconBlockRoot
        );

        // fix header, set a gas limit
        header.parent_beacon_block_root = Some(B256::with_last_byte(0x69));

        let mut executor = provider.executor(StateProviderDatabase::new(&db));

        // Now execute a block with the fixed header, ensure that it does not fail
        executor
            .execute_without_verification(
                &BlockWithSenders {
                    block: Block {
                        header: header.clone(),
                        body: BlockBody {
                            transactions: vec![],
                            ommers: vec![],
                            withdrawals: None,
                            requests: None,
                        },
                    },
                    senders: vec![],
                },
                U256::ZERO,
            )
            .unwrap();

        // check the actual storage of the contract - it should be:
        // * The storage value at header.timestamp % HISTORY_BUFFER_LENGTH should be
        // header.timestamp
        // * The storage value at header.timestamp % HISTORY_BUFFER_LENGTH + HISTORY_BUFFER_LENGTH
        //   // should be parent_beacon_block_root
        let history_buffer_length = 8191u64;
        let timestamp_index = header.timestamp % history_buffer_length;
        let parent_beacon_block_root_index =
            timestamp_index % history_buffer_length + history_buffer_length;

        // get timestamp storage and compare
        let timestamp_storage =
            executor.state.storage(BEACON_ROOTS_ADDRESS, U256::from(timestamp_index)).unwrap();
        assert_eq!(timestamp_storage, U256::from(header.timestamp));

        // get parent beacon block root storage and compare
        let parent_beacon_block_root_storage = executor
            .state
            .storage(BEACON_ROOTS_ADDRESS, U256::from(parent_beacon_block_root_index))
            .expect("storage value should exist");
        assert_eq!(parent_beacon_block_root_storage, U256::from(0x69));
    }

    #[test]
    fn eip_4788_no_code_cancun() {
        // This test ensures that we "silently fail" when cancun is active and there is no code at
        // // BEACON_ROOTS_ADDRESS
        let header = Header {
            timestamp: 1,
            number: 1,
            parent_beacon_block_root: Some(B256::with_last_byte(0x69)),
            excess_blob_gas: Some(0),
            ..Header::default()
        };

        let db = StateProviderTest::default();

        // DON'T deploy the contract at genesis
        let chain_spec = Arc::new(
            ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(1))
                .build(),
        );

        let provider = executor_provider(chain_spec);

        // attempt to execute an empty block with parent beacon block root, this should not fail
        provider
            .batch_executor(StateProviderDatabase::new(&db))
            .execute_and_verify_one(
                (
                    &BlockWithSenders {
                        block: Block {
                            header,
                            body: BlockBody {
                                transactions: vec![],
                                ommers: vec![],
                                withdrawals: None,
                                requests: None,
                            },
                        },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .expect(
                "Executing a block with no transactions while cancun is active should not fail",
            );
    }

    #[test]
    fn eip_4788_empty_account_call() {
        // This test ensures that we do not increment the nonce of an empty SYSTEM_ADDRESS account
        // // during the pre-block call

        let mut db = create_state_provider_with_beacon_root_contract();

        // insert an empty SYSTEM_ADDRESS
        db.insert_account(SYSTEM_ADDRESS, Account::default(), None, HashMap::default());

        let chain_spec = Arc::new(
            ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(1))
                .build(),
        );

        let provider = executor_provider(chain_spec);

        // construct the header for block one
        let header = Header {
            timestamp: 1,
            number: 1,
            parent_beacon_block_root: Some(B256::with_last_byte(0x69)),
            excess_blob_gas: Some(0),
            ..Header::default()
        };

        let mut executor = provider.batch_executor(StateProviderDatabase::new(&db));

        // attempt to execute an empty block with parent beacon block root, this should not fail
        executor
            .execute_and_verify_one(
                (
                    &BlockWithSenders {
                        block: Block {
                            header,
                            body: BlockBody {
                                transactions: vec![],
                                ommers: vec![],
                                withdrawals: None,
                                requests: None,
                            },
                        },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .expect(
                "Executing a block with no transactions while cancun is active should not fail",
            );

        // ensure that the nonce of the system address account has not changed
        let nonce = executor.state_mut().basic(SYSTEM_ADDRESS).unwrap().unwrap().nonce;
        assert_eq!(nonce, 0);
    }

    #[test]
    fn eip_4788_genesis_call() {
        let db = create_state_provider_with_beacon_root_contract();

        // activate cancun at genesis
        let chain_spec = Arc::new(
            ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(0))
                .build(),
        );

        let mut header = chain_spec.genesis_header().clone();
        let provider = executor_provider(chain_spec);
        let mut executor = provider.batch_executor(StateProviderDatabase::new(&db));

        // attempt to execute the genesis block with non-zero parent beacon block root, expect err
        header.parent_beacon_block_root = Some(B256::with_last_byte(0x69));
        let _err = executor
            .execute_and_verify_one(
                (
                    &BlockWithSenders {
                        block: Block { header: header.clone(), body: Default::default() },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .expect_err(
                "Executing genesis cancun block with non-zero parent beacon block root field
    should fail",
            );

        // fix header
        header.parent_beacon_block_root = Some(B256::ZERO);

        // now try to process the genesis block again, this time ensuring that a system contract
        // call does not occur
        executor
            .execute_and_verify_one(
                (
                    &BlockWithSenders {
                        block: Block { header, body: Default::default() },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .unwrap();

        // there is no system contract call so there should be NO STORAGE CHANGES
        // this means we'll check the transition state
        let transition_state = executor
            .state_mut()
            .transition_state
            .take()
            .expect("the evm should be initialized with bundle updates");

        // assert that it is the default (empty) transition state
        assert_eq!(transition_state, TransitionState::default());
    }

    #[test]
    fn eip_4788_high_base_fee() {
        // This test ensures that if we have a base fee, then we don't return an error when the
        // system contract is called, due to the gas price being less than the base fee.
        let header = Header {
            timestamp: 1,
            number: 1,
            parent_beacon_block_root: Some(B256::with_last_byte(0x69)),
            base_fee_per_gas: Some(u64::MAX.into()),
            excess_blob_gas: Some(0),
            ..Header::default()
        };

        let db = create_state_provider_with_beacon_root_contract();

        let chain_spec = Arc::new(
            ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(1))
                .build(),
        );

        let provider = executor_provider(chain_spec);

        // execute header
        let mut executor = provider.batch_executor(StateProviderDatabase::new(&db));

        // Now execute a block with the fixed header, ensure that it does not fail
        executor
            .execute_and_verify_one(
                (
                    &BlockWithSenders {
                        block: Block { header: header.clone(), body: Default::default() },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .unwrap();

        // check the actual storage of the contract - it should be:
        // * The storage value at header.timestamp % HISTORY_BUFFER_LENGTH should be
        // header.timestamp
        // * The storage value at header.timestamp % HISTORY_BUFFER_LENGTH + HISTORY_BUFFER_LENGTH
        //   // should be parent_beacon_block_root
        let history_buffer_length = 8191u64;
        let timestamp_index = header.timestamp % history_buffer_length;
        let parent_beacon_block_root_index =
            timestamp_index % history_buffer_length + history_buffer_length;

        // get timestamp storage and compare
        let timestamp_storage = executor
            .state_mut()
            .storage(BEACON_ROOTS_ADDRESS, U256::from(timestamp_index))
            .unwrap();
        assert_eq!(timestamp_storage, U256::from(header.timestamp));

        // get parent beacon block root storage and compare
        let parent_beacon_block_root_storage = executor
            .state_mut()
            .storage(BEACON_ROOTS_ADDRESS, U256::from(parent_beacon_block_root_index))
            .unwrap();
        assert_eq!(parent_beacon_block_root_storage, U256::from(0x69));
    }

    /// Create a state provider with blockhashes and the EIP-2935 system contract.
    fn create_state_provider_with_block_hashes(latest_block: u64) -> StateProviderTest {
        let mut db = StateProviderTest::default();
        for block_number in 0..=latest_block {
            db.insert_block_hash(block_number, keccak256(block_number.to_string()));
        }

        let blockhashes_contract_account = Account {
            balance: U256::ZERO,
            bytecode_hash: Some(keccak256(HISTORY_STORAGE_CODE.clone())),
            nonce: 1,
        };

        db.insert_account(
            HISTORY_STORAGE_ADDRESS,
            blockhashes_contract_account,
            Some(HISTORY_STORAGE_CODE.clone()),
            HashMap::default(),
        );

        db
    }

    #[test]
    fn eip_2935_pre_fork() {
        let db = create_state_provider_with_block_hashes(1);

        let chain_spec = Arc::new(
            ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .with_fork(EthereumHardfork::Prague, ForkCondition::Never)
                .build(),
        );

        let provider = executor_provider(chain_spec);
        let mut executor = provider.batch_executor(StateProviderDatabase::new(&db));

        // construct the header for block one
        let header = Header { timestamp: 1, number: 1, ..Header::default() };

        // attempt to execute an empty block, this should not fail
        executor
            .execute_and_verify_one(
                (
                    &BlockWithSenders {
                        block: Block { header, body: Default::default() },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .expect(
                "Executing a block with no transactions while Prague is active should not fail",
            );

        // ensure that the block hash was *not* written to storage, since this is before the fork
        // was activated
        //
        // we load the account first, because revm expects it to be
        // loaded
        executor.state_mut().basic(HISTORY_STORAGE_ADDRESS).unwrap();
        assert!(executor
            .state_mut()
            .storage(HISTORY_STORAGE_ADDRESS, U256::ZERO)
            .unwrap()
            .is_zero());
    }

    #[test]
    fn eip_2935_fork_activation_genesis() {
        let db = create_state_provider_with_block_hashes(0);

        let chain_spec = Arc::new(
            ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .with_fork(EthereumHardfork::Prague, ForkCondition::Timestamp(0))
                .build(),
        );

        let header = chain_spec.genesis_header().clone();
        let provider = executor_provider(chain_spec);
        let mut executor = provider.batch_executor(StateProviderDatabase::new(&db));

        // attempt to execute genesis block, this should not fail
        executor
            .execute_and_verify_one(
                (
                    &BlockWithSenders {
                        block: Block { header, body: Default::default() },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .expect(
                "Executing a block with no transactions while Prague is active should not fail",
            );

        // ensure that the block hash was *not* written to storage, since there are no blocks
        // preceding genesis
        //
        // we load the account first, because revm expects it to be
        // loaded
        executor.state_mut().basic(HISTORY_STORAGE_ADDRESS).unwrap();
        assert!(executor
            .state_mut()
            .storage(HISTORY_STORAGE_ADDRESS, U256::ZERO)
            .unwrap()
            .is_zero());
    }

    #[test]
    fn eip_2935_fork_activation_within_window_bounds() {
        let fork_activation_block = (BLOCKHASH_SERVE_WINDOW - 10) as u64;
        let db = create_state_provider_with_block_hashes(fork_activation_block);

        let chain_spec = Arc::new(
            ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .with_fork(EthereumHardfork::Prague, ForkCondition::Timestamp(1))
                .build(),
        );

        let header = Header {
            parent_hash: B256::random(),
            timestamp: 1,
            number: fork_activation_block,
            requests_root: Some(EMPTY_ROOT_HASH),
            ..Header::default()
        };
        let provider = executor_provider(chain_spec);
        let mut executor = provider.batch_executor(StateProviderDatabase::new(&db));

        // attempt to execute the fork activation block, this should not fail
        executor
            .execute_and_verify_one(
                (
                    &BlockWithSenders {
                        block: Block { header, body: Default::default() },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .expect(
                "Executing a block with no transactions while Prague is active should not fail",
            );

        // the hash for the ancestor of the fork activation block should be present
        assert!(executor.state_mut().basic(HISTORY_STORAGE_ADDRESS).unwrap().is_some());
        assert_ne!(
            executor
                .state_mut()
                .storage(HISTORY_STORAGE_ADDRESS, U256::from(fork_activation_block - 1))
                .unwrap(),
            U256::ZERO
        );

        // the hash of the block itself should not be in storage
        assert!(executor
            .state_mut()
            .storage(HISTORY_STORAGE_ADDRESS, U256::from(fork_activation_block))
            .unwrap()
            .is_zero());
    }

    #[test]
    fn eip_2935_fork_activation_outside_window_bounds() {
        let fork_activation_block = (BLOCKHASH_SERVE_WINDOW + 256) as u64;
        let db = create_state_provider_with_block_hashes(fork_activation_block);

        let chain_spec = Arc::new(
            ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .with_fork(EthereumHardfork::Prague, ForkCondition::Timestamp(1))
                .build(),
        );

        let provider = executor_provider(chain_spec);
        let mut executor = provider.batch_executor(StateProviderDatabase::new(&db));

        let header = Header {
            parent_hash: B256::random(),
            timestamp: 1,
            number: fork_activation_block,
            requests_root: Some(EMPTY_ROOT_HASH),
            ..Header::default()
        };

        // attempt to execute the fork activation block, this should not fail
        executor
            .execute_and_verify_one(
                (
                    &BlockWithSenders {
                        block: Block { header, body: Default::default() },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .expect(
                "Executing a block with no transactions while Prague is active should not fail",
            );

        // the hash for the ancestor of the fork activation block should be present
        assert!(executor.state_mut().basic(HISTORY_STORAGE_ADDRESS).unwrap().is_some());
        assert_ne!(
            executor
                .state_mut()
                .storage(
                    HISTORY_STORAGE_ADDRESS,
                    U256::from(fork_activation_block % BLOCKHASH_SERVE_WINDOW as u64 - 1)
                )
                .unwrap(),
            U256::ZERO
        );
    }

    #[test]
    fn eip_2935_state_transition_inside_fork() {
        let db = create_state_provider_with_block_hashes(2);

        let chain_spec = Arc::new(
            ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .with_fork(EthereumHardfork::Prague, ForkCondition::Timestamp(0))
                .build(),
        );

        let mut header = chain_spec.genesis_header().clone();
        header.requests_root = Some(EMPTY_ROOT_HASH);
        let header_hash = header.hash_slow();

        let provider = executor_provider(chain_spec);
        let mut executor = provider.batch_executor(StateProviderDatabase::new(&db));

        // attempt to execute the genesis block, this should not fail
        executor
            .execute_and_verify_one(
                (
                    &BlockWithSenders {
                        block: Block { header, body: Default::default() },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .expect(
                "Executing a block with no transactions while Prague is active should not fail",
            );

        // nothing should be written as the genesis has no ancestors
        //
        // we load the account first, because revm expects it to be
        // loaded
        executor.state_mut().basic(HISTORY_STORAGE_ADDRESS).unwrap();
        assert!(executor
            .state_mut()
            .storage(HISTORY_STORAGE_ADDRESS, U256::ZERO)
            .unwrap()
            .is_zero());

        // attempt to execute block 1, this should not fail
        let header = Header {
            parent_hash: header_hash,
            timestamp: 1,
            number: 1,
            requests_root: Some(EMPTY_ROOT_HASH),
            ..Header::default()
        };
        let header_hash = header.hash_slow();

        executor
            .execute_and_verify_one(
                (
                    &BlockWithSenders {
                        block: Block { header, body: Default::default() },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .expect(
                "Executing a block with no transactions while Prague is active should not fail",
            );

        // the block hash of genesis should now be in storage, but not block 1
        assert!(executor.state_mut().basic(HISTORY_STORAGE_ADDRESS).unwrap().is_some());
        assert_ne!(
            executor.state_mut().storage(HISTORY_STORAGE_ADDRESS, U256::ZERO).unwrap(),
            U256::ZERO
        );
        assert!(executor
            .state_mut()
            .storage(HISTORY_STORAGE_ADDRESS, U256::from(1))
            .unwrap()
            .is_zero());

        // attempt to execute block 2, this should not fail
        let header = Header {
            parent_hash: header_hash,
            timestamp: 1,
            number: 2,
            requests_root: Some(EMPTY_ROOT_HASH),
            ..Header::default()
        };

        executor
            .execute_and_verify_one(
                (
                    &BlockWithSenders {
                        block: Block { header, body: Default::default() },
                        senders: vec![],
                    },
                    U256::ZERO,
                )
                    .into(),
            )
            .expect(
                "Executing a block with no transactions while Prague is active should not fail",
            );

        // the block hash of genesis and block 1 should now be in storage, but not block 2
        assert!(executor.state_mut().basic(HISTORY_STORAGE_ADDRESS).unwrap().is_some());
        assert_ne!(
            executor.state_mut().storage(HISTORY_STORAGE_ADDRESS, U256::ZERO).unwrap(),
            U256::ZERO
        );
        assert_ne!(
            executor.state_mut().storage(HISTORY_STORAGE_ADDRESS, U256::from(1)).unwrap(),
            U256::ZERO
        );
        assert!(executor
            .state_mut()
            .storage(HISTORY_STORAGE_ADDRESS, U256::from(2))
            .unwrap()
            .is_zero());
    }

    #[test]
    fn eip_7002() {
        let chain_spec = Arc::new(
            ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .with_fork(EthereumHardfork::Prague, ForkCondition::Timestamp(0))
                .build(),
        );

        let mut db = create_state_provider_with_withdrawal_requests_contract();

        let secp = Secp256k1::new();
        let sender_key_pair = Keypair::new(&secp, &mut generators::rng());
        let sender_address = public_key_to_address(sender_key_pair.public_key());

        db.insert_account(
            sender_address,
            Account { nonce: 1, balance: U256::from(ETH_TO_WEI), bytecode_hash: None },
            None,
            HashMap::default(),
        );

        // https://github.com/lightclient/7002asm/blob/e0d68e04d15f25057af7b6d180423d94b6b3bdb3/test/Contract.t.sol.in#L49-L64
        let validator_public_key = fixed_bytes!("111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");
        let withdrawal_amount = fixed_bytes!("2222222222222222");
        let input: Bytes = [&validator_public_key[..], &withdrawal_amount[..]].concat().into();
        assert_eq!(input.len(), 56);

        let mut header = chain_spec.genesis_header().clone();
        header.gas_limit = 1_500_000;
        header.gas_used = 134_807;
        header.receipts_root =
            b256!("b31a3e47b902e9211c4d349af4e4c5604ce388471e79ca008907ae4616bb0ed3");

        let tx = sign_tx_with_key_pair(
            sender_key_pair,
            Transaction::Legacy(TxLegacy {
                chain_id: Some(chain_spec.chain.id()),
                nonce: 1,
                gas_price: header.base_fee_per_gas.unwrap() as u128,
                gas_limit: 134_807,
                to: TxKind::Call(WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS),
                // `MIN_WITHDRAWAL_REQUEST_FEE`
                value: U256::from(1),
                input,
            }),
        );

        let provider = executor_provider(chain_spec);

        let executor = provider.executor(StateProviderDatabase::new(&db));

        let BlockExecutionOutput { receipts, requests, .. } = executor
            .execute(
                (
                    &Block {
                        header,
                        body: BlockBody { transactions: vec![tx], ..Default::default() },
                    }
                    .with_recovered_senders()
                    .unwrap(),
                    U256::ZERO,
                )
                    .into(),
            )
            .unwrap();

        let receipt = receipts.first().unwrap();
        assert!(receipt.success);

        let request = requests.first().unwrap();
        let withdrawal_request = request.as_withdrawal_request().unwrap();
        assert_eq!(withdrawal_request.source_address, sender_address);
        assert_eq!(withdrawal_request.validator_pubkey, validator_public_key);
        assert_eq!(withdrawal_request.amount, u64::from_be_bytes(withdrawal_amount.into()));
    }

    #[test]
    fn block_gas_limit_error() {
        // Create a chain specification with fork conditions set for Prague
        let chain_spec = Arc::new(
            ChainSpecBuilder::from(&*MAINNET)
                .shanghai_activated()
                .with_fork(EthereumHardfork::Prague, ForkCondition::Timestamp(0))
                .build(),
        );

        // Create a state provider with the withdrawal requests contract pre-deployed
        let mut db = create_state_provider_with_withdrawal_requests_contract();

        // Initialize Secp256k1 for key pair generation
        let secp = Secp256k1::new();
        // Generate a new key pair for the sender
        let sender_key_pair = Keypair::new(&secp, &mut generators::rng());
        // Get the sender's address from the public key
        let sender_address = public_key_to_address(sender_key_pair.public_key());

        // Insert the sender account into the state with a nonce of 1 and a balance of 1 ETH in Wei
        db.insert_account(
            sender_address,
            Account { nonce: 1, balance: U256::from(ETH_TO_WEI), bytecode_hash: None },
            None,
            HashMap::default(),
        );

        // Define the validator public key and withdrawal amount as fixed bytes
        let validator_public_key = fixed_bytes!("111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");
        let withdrawal_amount = fixed_bytes!("2222222222222222");
        // Concatenate the validator public key and withdrawal amount into a single byte array
        let input: Bytes = [&validator_public_key[..], &withdrawal_amount[..]].concat().into();
        // Ensure the input length is 56 bytes
        assert_eq!(input.len(), 56);

        // Create a genesis block header with a specified gas limit and gas used
        let mut header = chain_spec.genesis_header().clone();
        header.gas_limit = 1_500_000;
        header.gas_used = 134_807;
        header.receipts_root =
            b256!("b31a3e47b902e9211c4d349af4e4c5604ce388471e79ca008907ae4616bb0ed3");

        // Create a transaction with a gas limit higher than the block gas limit
        let tx = sign_tx_with_key_pair(
            sender_key_pair,
            Transaction::Legacy(TxLegacy {
                chain_id: Some(chain_spec.chain.id()),
                nonce: 1,
                gas_price: header.base_fee_per_gas.unwrap() as u128,
                gas_limit: 2_500_000, // higher than block gas limit
                to: TxKind::Call(WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS),
                value: U256::from(1),
                input,
            }),
        );

        // Create an executor from the state provider
        let executor = executor_provider(chain_spec).executor(StateProviderDatabase::new(&db));

        // Execute the block and capture the result
        let exec_result = executor.execute(
            (
                &Block { header, body: BlockBody { transactions: vec![tx], ..Default::default() } }
                    .with_recovered_senders()
                    .unwrap(),
                U256::ZERO,
            )
                .into(),
        );

        // Check if the execution result is an error and assert the specific error type
        match exec_result {
            Ok(_) => panic!("Expected block gas limit error"),
            Err(err) => assert_eq!(
                *err.as_validation().unwrap(),
                BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit: 2_500_000,
                    block_available_gas: 1_500_000,
                }
            ),
        }
    }
}
