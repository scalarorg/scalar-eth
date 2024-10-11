use crate::executor::parallel::ParallelEvmContext;
use alloc::vec::Vec;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use reth_chainspec::{ChainSpec, EthereumHardforks};
use reth_ethereum_forks::{EthereumHardfork, Head};
use reth_evm::{ConfigureEvm, ConfigureEvmEnv, NextBlockEnvAttributes};
use reth_primitives::constants::EIP1559_INITIAL_BASE_FEE;
use reth_primitives::{transaction::FillTxEnv, Header, TransactionSigned};
use revm::{
    handler::register::EvmHandler, inspector_handle_register, precompile::PrecompileSpecId,
    ContextPrecompiles, Database, Evm, EvmBuilder, GetInspector,
};
use revm_primitives::{
    address, AnalysisKind, BlobExcessGasAndPrice, BlockEnv, CfgEnv, CfgEnvWithHandlerCfg, Env,
    Precompile, PrecompileOutput, PrecompileResult, SpecId, TxEnv,
};
use std::sync::Arc;

/// Returns the revm [`SpecId`](revm_primitives::SpecId) at the given timestamp.
///
/// # Note
///
/// This is only intended to be used after the merge, when hardforks are activated by
/// timestamp.
pub fn revm_spec_by_timestamp_after_merge(
    chain_spec: &ChainSpec,
    timestamp: u64,
) -> revm_primitives::SpecId {
    if chain_spec.is_prague_active_at_timestamp(timestamp) {
        revm_primitives::PRAGUE
    } else if chain_spec.is_cancun_active_at_timestamp(timestamp) {
        revm_primitives::CANCUN
    } else if chain_spec.is_shanghai_active_at_timestamp(timestamp) {
        revm_primitives::SHANGHAI
    } else {
        revm_primitives::MERGE
    }
}

/// Map the latest active hardfork at the given block to a revm [`SpecId`](revm_primitives::SpecId).
pub fn revm_spec(chain_spec: &ChainSpec, block: &Head) -> revm_primitives::SpecId {
    if chain_spec.fork(EthereumHardfork::Prague).active_at_head(block) {
        revm_primitives::PRAGUE
    } else if chain_spec.fork(EthereumHardfork::Cancun).active_at_head(block) {
        revm_primitives::CANCUN
    } else if chain_spec.fork(EthereumHardfork::Shanghai).active_at_head(block) {
        revm_primitives::SHANGHAI
    } else if chain_spec.fork(EthereumHardfork::Paris).active_at_head(block) {
        revm_primitives::MERGE
    } else if chain_spec.fork(EthereumHardfork::London).active_at_head(block) {
        revm_primitives::LONDON
    } else if chain_spec.fork(EthereumHardfork::Berlin).active_at_head(block) {
        revm_primitives::BERLIN
    } else if chain_spec.fork(EthereumHardfork::Istanbul).active_at_head(block) {
        revm_primitives::ISTANBUL
    } else if chain_spec.fork(EthereumHardfork::Petersburg).active_at_head(block) {
        revm_primitives::PETERSBURG
    } else if chain_spec.fork(EthereumHardfork::Byzantium).active_at_head(block) {
        revm_primitives::BYZANTIUM
    } else if chain_spec.fork(EthereumHardfork::SpuriousDragon).active_at_head(block) {
        revm_primitives::SPURIOUS_DRAGON
    } else if chain_spec.fork(EthereumHardfork::Tangerine).active_at_head(block) {
        revm_primitives::TANGERINE
    } else if chain_spec.fork(EthereumHardfork::Homestead).active_at_head(block) {
        revm_primitives::HOMESTEAD
    } else if chain_spec.fork(EthereumHardfork::Frontier).active_at_head(block) {
        revm_primitives::FRONTIER
    } else {
        panic!(
            "invalid hardfork chainspec: expected at least one hardfork, got {:?}",
            chain_spec.hardforks
        )
    }
}

/// Ethereum-related EVM configuration.
#[derive(Debug, Clone)]
pub struct EthEvmConfig {
    /// The chain specification for the Ethereum network.
    pub(crate) chain_spec: Arc<ChainSpec>,
}

impl EthEvmConfig {
    /// Creates a new Ethereum EVM configuration with the given chain spec.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec }
    }

    /// Returns the chain spec associated with this configuration.
    pub fn chain_spec(&self) -> &ChainSpec {
        &self.chain_spec
    }
}

impl ConfigureEvmEnv for EthEvmConfig {
    type Header = Header;

    fn fill_tx_env(&self, tx_env: &mut TxEnv, transaction: &TransactionSigned, sender: Address) {
        transaction.fill_tx_env(tx_env, sender);
    }

    fn fill_tx_env_system_contract_call(
        &self,
        env: &mut Env,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) {
        #[allow(clippy::needless_update)] // side-effect of optimism fields
        let tx = TxEnv {
            caller,
            transact_to: TxKind::Call(contract),
            // Explicitly set nonce to None so revm does not do any nonce checks
            nonce: None,
            gas_limit: 30_000_000,
            value: U256::ZERO,
            data,
            // Setting the gas price to zero enforces that no value is transferred as part of the
            // call, and that the call will not count against the block's gas limit
            gas_price: U256::ZERO,
            // The chain ID check is not relevant here and is disabled if set to None
            chain_id: None,
            // Setting the gas priority fee to None ensures the effective gas price is derived from
            // the `gas_price` field, which we need to be zero
            gas_priority_fee: None,
            access_list: Vec::new(),
            // blob fields can be None for this tx
            blob_hashes: Vec::new(),
            max_fee_per_blob_gas: None,
            // TODO remove this once this crate is no longer built with optimism
            ..Default::default()
        };
        env.tx = tx;

        // ensure the block gas limit is >= the tx
        env.block.gas_limit = U256::from(env.tx.gas_limit);

        // disable the base fee check for this call by setting the base fee to zero
        env.block.basefee = U256::ZERO;
    }

    fn fill_cfg_env(
        &self,
        cfg_env: &mut CfgEnvWithHandlerCfg,
        header: &Header,
        total_difficulty: U256,
    ) {
        let spec_id = revm_spec(
            self.chain_spec(),
            &Head {
                number: header.number,
                timestamp: header.timestamp,
                difficulty: header.difficulty,
                total_difficulty,
                hash: Default::default(),
            },
        );

        cfg_env.chain_id = self.chain_spec.chain().id();
        cfg_env.perf_analyse_created_bytecodes = AnalysisKind::Analyse;

        cfg_env.handler_cfg.spec_id = spec_id;
    }

    fn next_cfg_and_block_env(
        &self,
        parent: &Self::Header,
        attributes: NextBlockEnvAttributes,
    ) -> (CfgEnvWithHandlerCfg, BlockEnv) {
        // configure evm env based on parent block
        let cfg = CfgEnv::default().with_chain_id(self.chain_spec.chain().id());

        // ensure we're not missing any timestamp based hardforks
        let spec_id = revm_spec_by_timestamp_after_merge(&self.chain_spec, attributes.timestamp);

        // if the parent block did not have excess blob gas (i.e. it was pre-cancun), but it is
        // cancun now, we need to set the excess blob gas to the default value
        let blob_excess_gas_and_price = parent
            .next_block_excess_blob_gas()
            .or_else(|| {
                if spec_id == SpecId::CANCUN {
                    // default excess blob gas is zero
                    Some(0)
                } else {
                    None
                }
            })
            .map(|excess_blob_gas| BlobExcessGasAndPrice::new(excess_blob_gas as u64));

        let mut basefee = parent.next_block_base_fee(
            self.chain_spec.base_fee_params_at_timestamp(attributes.timestamp),
        );

        let mut gas_limit = U256::from(parent.gas_limit);

        // If we are on the London fork boundary, we need to multiply the parent's gas limit by the
        // elasticity multiplier to get the new gas limit.
        if self.chain_spec.fork(EthereumHardfork::London).transitions_at_block(parent.number + 1) {
            let elasticity_multiplier = self
                .chain_spec
                .base_fee_params_at_timestamp(attributes.timestamp)
                .elasticity_multiplier;

            // multiply the gas limit by the elasticity multiplier
            gas_limit *= U256::from(elasticity_multiplier);

            // set the base fee to the initial base fee from the EIP-1559 spec
            basefee = Some(EIP1559_INITIAL_BASE_FEE.into())
        }

        let block_env = BlockEnv {
            number: U256::from(parent.number + 1),
            coinbase: attributes.suggested_fee_recipient,
            timestamp: U256::from(attributes.timestamp),
            difficulty: U256::ZERO,
            prevrandao: Some(attributes.prev_randao),
            gas_limit,
            // calculate basefee based on parent block's gas usage
            basefee: basefee.map(U256::from).unwrap_or_default(),
            // calculate excess gas based on parent block's blob gas usage
            blob_excess_gas_and_price,
        };

        (CfgEnvWithHandlerCfg::new_with_spec_id(cfg, spec_id), block_env)
    }
}

impl ConfigureEvm for EthEvmConfig {
    type DefaultExternalContext<'a> = ();

    fn default_external_context<'a>(&self) -> Self::DefaultExternalContext<'a> {}
}
/// Sequential EVM configuration
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SequencialEvmConfig {
    /// Wrapper around mainnet configuration
    inner: EthEvmConfig,
}

impl SequencialEvmConfig {
    /// Creates a new sequential EVM configuration with the given chain spec.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { inner: EthEvmConfig::new(chain_spec) }
    }
}

impl SequencialEvmConfig {
    /// Sets the precompiles to the EVM handler
    ///
    /// This will be invoked when the EVM is created via [ConfigureEvm::evm] or
    /// [ConfigureEvm::evm_with_inspector]
    ///
    /// This will use the default mainnet precompiles and add additional precompiles.
    pub fn set_precompiles<EXT, DB>(handler: &mut EvmHandler<'_, EXT, DB>)
    where
        DB: Database,
    {
        // first we need the evm spec id, which determines the precompiles
        let spec_id = handler.cfg.spec_id;

        // install the precompiles
        handler.pre_execution.load_precompiles = Arc::new(move || {
            let mut precompiles = ContextPrecompiles::new(PrecompileSpecId::from_spec_id(spec_id));
            precompiles.extend([(
                address!("0000000000000000000000000000000000000999"),
                Precompile::Env(Self::my_precompile).into(),
            )]);
            precompiles
        });
    }

    /// A custom precompile that does nothing
    fn my_precompile(_data: &Bytes, _gas: u64, _env: &Env) -> PrecompileResult {
        Ok(PrecompileOutput::new(0, Bytes::new()))
    }
}

impl ConfigureEvmEnv for SequencialEvmConfig {
    type Header = Header;

    fn fill_tx_env(&self, tx_env: &mut TxEnv, transaction: &TransactionSigned, sender: Address) {
        self.inner.fill_tx_env(tx_env, transaction, sender);
    }

    fn fill_tx_env_system_contract_call(
        &self,
        env: &mut Env,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) {
        self.inner.fill_tx_env_system_contract_call(env, caller, contract, data);
    }

    fn fill_cfg_env(
        &self,
        cfg_env: &mut CfgEnvWithHandlerCfg,
        header: &Self::Header,
        total_difficulty: U256,
    ) {
        self.inner.fill_cfg_env(cfg_env, header, total_difficulty);
    }

    fn next_cfg_and_block_env(
        &self,
        parent: &Self::Header,
        attributes: NextBlockEnvAttributes,
    ) -> (CfgEnvWithHandlerCfg, BlockEnv) {
        self.inner.next_cfg_and_block_env(parent, attributes)
    }
}

/// Implement the EVM configuration for the custom EVM
/// ParallelEvmContext is used to keep inmemory state for the EVM
impl ConfigureEvm for SequencialEvmConfig {
    type DefaultExternalContext<'a> = ();

    fn evm<DB: Database>(&self, db: DB) -> Evm<'_, Self::DefaultExternalContext<'_>, DB> {
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(self.default_external_context())
            // add additional precompiles
            .append_handler_register(SequencialEvmConfig::set_precompiles)
            .build()
    }

    fn evm_with_inspector<DB, I>(&self, db: DB, inspector: I) -> Evm<'_, I, DB>
    where
        DB: Database,
        I: GetInspector<DB>,
    {
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(inspector)
            // add additional precompiles
            .append_handler_register(SequencialEvmConfig::set_precompiles)
            .append_handler_register(inspector_handle_register)
            .build()
    }

    fn default_external_context<'a>(&self) -> Self::DefaultExternalContext<'a> {}
}
/// Parallel EVM configuration
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParallelEvmConfig {
    /// Wrapper around mainnet configuration
    inner: EthEvmConfig,
    /// Parallel EVM external context, stores inmemory state
    pub context: ParallelEvmContext,
}

impl ParallelEvmConfig {
    /// Creates a new `ParallelEvmConfig` instance.
    ///
    /// # Arguments
    ///
    /// * `chain_spec` - An `Arc<ChainSpec>` containing the chain specification.
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { inner: EthEvmConfig::new(chain_spec), context: ParallelEvmContext::default() }
    }
}

impl ParallelEvmConfig {
    /// Sets the precompiles to the EVM handler
    ///
    /// This will be invoked when the EVM is created via [ConfigureEvm::evm] or
    /// [ConfigureEvm::evm_with_inspector]
    ///
    /// This will use the default mainnet precompiles and add additional precompiles.
    pub fn set_precompiles<EXT, DB>(handler: &mut EvmHandler<'_, EXT, DB>)
    where
        DB: Database,
    {
        // first we need the evm spec id, which determines the precompiles
        let spec_id = handler.cfg.spec_id;

        // install the precompiles
        handler.pre_execution.load_precompiles = Arc::new(move || {
            let mut precompiles = ContextPrecompiles::new(PrecompileSpecId::from_spec_id(spec_id));
            precompiles.extend([(
                address!("0000000000000000000000000000000000000999"),
                Precompile::Env(Self::my_precompile).into(),
            )]);
            precompiles
        });
    }

    /// A custom precompile that does nothing
    fn my_precompile(_data: &Bytes, _gas: u64, _env: &Env) -> PrecompileResult {
        Ok(PrecompileOutput::new(0, Bytes::new()))
    }
}

impl ConfigureEvmEnv for ParallelEvmConfig {
    type Header = Header;

    fn fill_tx_env(&self, tx_env: &mut TxEnv, transaction: &TransactionSigned, sender: Address) {
        self.inner.fill_tx_env(tx_env, transaction, sender);
    }

    fn fill_tx_env_system_contract_call(
        &self,
        env: &mut Env,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) {
        self.inner.fill_tx_env_system_contract_call(env, caller, contract, data);
    }

    fn fill_cfg_env(
        &self,
        cfg_env: &mut CfgEnvWithHandlerCfg,
        header: &Self::Header,
        total_difficulty: U256,
    ) {
        self.inner.fill_cfg_env(cfg_env, header, total_difficulty);
    }

    fn next_cfg_and_block_env(
        &self,
        parent: &Self::Header,
        attributes: NextBlockEnvAttributes,
    ) -> (CfgEnvWithHandlerCfg, BlockEnv) {
        self.inner.next_cfg_and_block_env(parent, attributes)
    }
}

/// Implement the EVM configuration for the custom EVM
/// ParallelEvmContext is used to keep inmemory state for the EVM
impl ConfigureEvm for ParallelEvmConfig {
    type DefaultExternalContext<'a> = ParallelEvmContext;

    fn evm<DB: Database>(&self, db: DB) -> Evm<'_, Self::DefaultExternalContext<'_>, DB> {
        let context = self.default_external_context();
        //Check if the context is uninitialized then initialize it with genesis state
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(context)
            // add additional precompiles
            .append_handler_register(ParallelEvmConfig::set_precompiles)
            .build()
    }

    fn evm_with_inspector<DB, I>(&self, db: DB, inspector: I) -> Evm<'_, I, DB>
    where
        DB: Database,
        I: GetInspector<DB>,
    {
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(inspector)
            // add additional precompiles
            .append_handler_register(ParallelEvmConfig::set_precompiles)
            .append_handler_register(inspector_handle_register)
            .build()
    }

    fn default_external_context<'a>(&self) -> Self::DefaultExternalContext<'a> {
        // Self::DefaultExternalContext::default()
        self.context.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use reth_chainspec::{ChainSpecBuilder, MAINNET};

    #[test]
    fn test_revm_spec_by_timestamp_after_merge() {
        assert_eq!(
            revm_spec_by_timestamp_after_merge(
                &ChainSpecBuilder::mainnet().cancun_activated().build(),
                0
            ),
            revm_primitives::CANCUN
        );
        assert_eq!(
            revm_spec_by_timestamp_after_merge(
                &ChainSpecBuilder::mainnet().shanghai_activated().build(),
                0
            ),
            revm_primitives::SHANGHAI
        );
        assert_eq!(
            revm_spec_by_timestamp_after_merge(&ChainSpecBuilder::mainnet().build(), 0),
            revm_primitives::MERGE
        );
    }

    #[test]
    fn test_to_revm_spec() {
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().cancun_activated().build(), &Head::default()),
            revm_primitives::CANCUN
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().shanghai_activated().build(), &Head::default()),
            revm_primitives::SHANGHAI
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().paris_activated().build(), &Head::default()),
            revm_primitives::MERGE
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().london_activated().build(), &Head::default()),
            revm_primitives::LONDON
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().berlin_activated().build(), &Head::default()),
            revm_primitives::BERLIN
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().istanbul_activated().build(), &Head::default()),
            revm_primitives::ISTANBUL
        );
        assert_eq!(
            revm_spec(
                &ChainSpecBuilder::mainnet().petersburg_activated().build(),
                &Head::default()
            ),
            revm_primitives::PETERSBURG
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().byzantium_activated().build(), &Head::default()),
            revm_primitives::BYZANTIUM
        );
        assert_eq!(
            revm_spec(
                &ChainSpecBuilder::mainnet().spurious_dragon_activated().build(),
                &Head::default()
            ),
            revm_primitives::SPURIOUS_DRAGON
        );
        assert_eq!(
            revm_spec(
                &ChainSpecBuilder::mainnet().tangerine_whistle_activated().build(),
                &Head::default()
            ),
            revm_primitives::TANGERINE
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().homestead_activated().build(), &Head::default()),
            revm_primitives::HOMESTEAD
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().frontier_activated().build(), &Head::default()),
            revm_primitives::FRONTIER
        );
    }

    #[test]
    fn test_eth_spec() {
        assert_eq!(
            revm_spec(&MAINNET, &Head { timestamp: 1710338135, ..Default::default() }),
            revm_primitives::CANCUN
        );
        assert_eq!(
            revm_spec(&MAINNET, &Head { timestamp: 1681338455, ..Default::default() }),
            revm_primitives::SHANGHAI
        );

        assert_eq!(
            revm_spec(
                &MAINNET,
                &Head {
                    total_difficulty: U256::from(58_750_000_000_000_000_000_010_u128),
                    difficulty: U256::from(10_u128),
                    ..Default::default()
                }
            ),
            revm_primitives::MERGE
        );
        // TTD trumps the block number
        assert_eq!(
            revm_spec(
                &MAINNET,
                &Head {
                    number: 15537394 - 10,
                    total_difficulty: U256::from(58_750_000_000_000_000_000_010_u128),
                    difficulty: U256::from(10_u128),
                    ..Default::default()
                }
            ),
            revm_primitives::MERGE
        );
        assert_eq!(
            revm_spec(&MAINNET, &Head { number: 15537394 - 10, ..Default::default() }),
            revm_primitives::LONDON
        );
        assert_eq!(
            revm_spec(&MAINNET, &Head { number: 12244000 + 10, ..Default::default() }),
            revm_primitives::BERLIN
        );
        assert_eq!(
            revm_spec(&MAINNET, &Head { number: 12244000 - 10, ..Default::default() }),
            revm_primitives::ISTANBUL
        );
        assert_eq!(
            revm_spec(&MAINNET, &Head { number: 7280000 + 10, ..Default::default() }),
            revm_primitives::PETERSBURG
        );
        assert_eq!(
            revm_spec(&MAINNET, &Head { number: 7280000 - 10, ..Default::default() }),
            revm_primitives::BYZANTIUM
        );
        assert_eq!(
            revm_spec(&MAINNET, &Head { number: 2675000 + 10, ..Default::default() }),
            revm_primitives::SPURIOUS_DRAGON
        );
        assert_eq!(
            revm_spec(&MAINNET, &Head { number: 2675000 - 10, ..Default::default() }),
            revm_primitives::TANGERINE
        );
        assert_eq!(
            revm_spec(&MAINNET, &Head { number: 1150000 + 10, ..Default::default() }),
            revm_primitives::HOMESTEAD
        );
        assert_eq!(
            revm_spec(&MAINNET, &Head { number: 1150000 - 10, ..Default::default() }),
            revm_primitives::FRONTIER
        );
    }
}
