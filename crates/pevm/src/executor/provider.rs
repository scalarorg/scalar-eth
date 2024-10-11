//! Ethereum block executor.

use super::parallel::ParallelEvmContext;
use super::{
    EthBatchExecutor, EthBlockExecutor, ParallelEthBatchExecutor, ParallelEthBlockExecutor,
};
use crate::EthEvmConfig;
use alloc::sync::Arc;
use core::fmt::Display;
use reth_chainspec::{ChainSpec, MAINNET};
use reth_evm::{
    execute::{BlockExecutorProvider, ProviderError},
    ConfigureEvm,
};
use reth_primitives::Header;
use reth_revm::{batch::BlockBatchRecord, db::State};
use revm_primitives::db::Database;
/// Provides executors to execute regular ethereum blocks
#[derive(Debug, Clone)]
pub struct EthExecutorProvider<EvmConfig = EthEvmConfig> {
    pub(super) chain_spec: Arc<ChainSpec>,
    pub(super) evm_config: EvmConfig,
}

impl EthExecutorProvider {
    /// Creates a new default ethereum executor provider.
    pub fn ethereum(chain_spec: Arc<ChainSpec>) -> Self {
        Self::new(chain_spec.clone(), EthEvmConfig::new(chain_spec))
    }

    /// Returns a new provider for the mainnet.
    pub fn mainnet() -> Self {
        Self::ethereum(MAINNET.clone())
    }
}

impl<EvmConfig> EthExecutorProvider<EvmConfig> {
    /// Creates a new executor provider.
    pub const fn new(chain_spec: Arc<ChainSpec>, evm_config: EvmConfig) -> Self {
        Self { chain_spec, evm_config }
    }
}

impl<EvmConfig> EthExecutorProvider<EvmConfig>
where
    EvmConfig: ConfigureEvm<Header = Header>,
{
    fn eth_executor<DB>(&self, db: DB) -> EthBlockExecutor<EvmConfig, DB>
    where
        DB: Database<Error: Into<ProviderError>>,
    {
        EthBlockExecutor::new(
            self.chain_spec.clone(),
            self.evm_config.clone(),
            State::builder().with_database(db).with_bundle_update().without_state_clear().build(),
        )
    }
}

impl<EvmConfig> BlockExecutorProvider for EthExecutorProvider<EvmConfig>
where
    EvmConfig: ConfigureEvm<Header = Header>,
{
    type Executor<DB: Database<Error: Into<ProviderError> + Display>> =
        EthBlockExecutor<EvmConfig, DB>;

    type BatchExecutor<DB: Database<Error: Into<ProviderError> + Display>> =
        EthBatchExecutor<EvmConfig, DB>;

    fn executor<DB>(&self, db: DB) -> Self::Executor<DB>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        self.eth_executor(db)
    }

    fn batch_executor<DB>(&self, db: DB) -> Self::BatchExecutor<DB>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        let executor = self.eth_executor(db);
        EthBatchExecutor { executor, batch_record: BlockBatchRecord::default() }
    }
}

/// Parallel executor provider for creating pevm executor
#[derive(Debug, Clone)]
pub struct ParallelExecutorProvider<EvmConfig = EthEvmConfig> {
    pub(super) chain_spec: Arc<ChainSpec>,
    pub(super) evm_config: EvmConfig,
}

impl ParallelExecutorProvider {
    /// Creates a new default ethereum executor provider.
    pub fn ethereum(chain_spec: Arc<ChainSpec>) -> Self {
        Self::new(chain_spec.clone(), EthEvmConfig::new(chain_spec))
    }

    /// Returns a new provider for the mainnet.
    pub fn mainnet() -> Self {
        Self::ethereum(MAINNET.clone())
    }
}

impl<EvmConfig> ParallelExecutorProvider<EvmConfig> {
    /// Creates a new executor provider.
    pub fn new(chain_spec: Arc<ChainSpec>, evm_config: EvmConfig) -> Self {
        Self { chain_spec, evm_config }
    }
}

impl<EvmConfig> ParallelExecutorProvider<EvmConfig>
where
    EvmConfig: ConfigureEvm<Header = Header>,
{
    fn eth_executor<DB>(&self, db: DB) -> ParallelEthBlockExecutor<EvmConfig, DB>
    where
        DB: Database<Error: Into<ProviderError>>,
    {
        ParallelEthBlockExecutor::new(
            self.chain_spec.clone(),
            self.evm_config.clone(),
            State::builder().with_database(db).with_bundle_update().without_state_clear().build(),
        )
    }
}

impl<EvmConfig> BlockExecutorProvider for ParallelExecutorProvider<EvmConfig>
where
    EvmConfig:
        for<'a> ConfigureEvm<Header = Header, DefaultExternalContext<'a> = ParallelEvmContext>,
{
    type Executor<DB: Database<Error: Into<ProviderError> + Display>> =
        ParallelEthBlockExecutor<EvmConfig, DB>;

    type BatchExecutor<DB: Database<Error: Into<ProviderError> + Display>> =
        ParallelEthBatchExecutor<EvmConfig, DB>;

    fn executor<DB>(&self, db: DB) -> Self::Executor<DB>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        self.eth_executor(db)
    }

    fn batch_executor<DB>(&self, db: DB) -> Self::BatchExecutor<DB>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        let executor = self.eth_executor(db);
        ParallelEthBatchExecutor { executor, batch_record: BlockBatchRecord::default() }
    }
}
