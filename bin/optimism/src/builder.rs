use reth::{
    builder::{
        components::{ExecutorBuilder, PayloadServiceBuilder},
        BuilderContext,
    },
    payload::{EthBuiltPayload, EthPayloadBuilderAttributes},
    rpc::types::engine::PayloadAttributes,
    transaction_pool::TransactionPool,
};
use reth_chainspec::ChainSpec;
use reth_node_api::{FullNodeTypes, NodeTypes, NodeTypesWithEngine, PayloadTypes};
use reth_node_ethereum::node::EthereumPayloadBuilder;
use scalar_pevm::executor::{EthExecutorProvider, ParallelExecutorProvider};
use scalar_pevm::{ParallelEvmConfig, SequencialEvmConfig};

/// Builds a regular ethereum block executor that uses the custom EVM.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct SequentialExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for SequentialExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec>>,
{
    type EVM = SequencialEvmConfig;
    type Executor = EthExecutorProvider<Self::EVM>;
    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        Ok((
            SequencialEvmConfig::new(ctx.chain_spec()),
            EthExecutorProvider::new(ctx.chain_spec(), SequencialEvmConfig::new(ctx.chain_spec())),
        ))
    }
}

/// Builds a regular ethereum block executor that uses the custom EVM.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct ParallelExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for ParallelExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec>>,
{
    type EVM = ParallelEvmConfig;
    type Executor = ParallelExecutorProvider<Self::EVM>;
    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        Ok((
            ParallelEvmConfig::new(ctx.chain_spec()),
            ParallelExecutorProvider::new(
                ctx.chain_spec(),
                ParallelEvmConfig::new(ctx.chain_spec()),
            ),
        ))
    }
}

/// Builds a regular ethereum block executor that uses the custom EVM.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct ScalarPayloadBuilder {
    inner: EthereumPayloadBuilder,
}

impl<Types, Node, Pool> PayloadServiceBuilder<Node, Pool> for ScalarPayloadBuilder
where
    Types: NodeTypesWithEngine<ChainSpec = ChainSpec>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool + Unpin + 'static,
    Types::Engine: PayloadTypes<
        BuiltPayload = EthBuiltPayload,
        PayloadAttributes = PayloadAttributes,
        PayloadBuilderAttributes = EthPayloadBuilderAttributes,
    >,
{
    async fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<reth::payload::PayloadBuilderHandle<Types::Engine>> {
        self.inner.spawn(ParallelEvmConfig::new(ctx.chain_spec()), ctx, pool)
    }
}
