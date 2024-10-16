use reth::{
    providers::providers::{BlockchainProvider2, ProviderNodeTypes},
    rpc::api::eth::{helpers::AddDevSigners, FullEthApiServer},
    tasks::TaskExecutor,
};
use reth_chainspec::ChainSpec;
use reth_node_api::{FullNodeTypes, NodeAddOns, NodeTypesWithEngine};
use reth_node_builder::{
    engine_tree_config::TreeConfig, rpc::EthApiBuilderProvider, EngineNodeLauncher, LaunchContext,
    LaunchNode, NodeAdapter, NodeBuilderWithComponents, NodeComponentsBuilder, NodeConfig,
    NodeHandle,
};
use scalar_pevm::{
    executor::parallel::{chain::PevmEthereum, types::BlockExecutionRequest},
    ParallelEthEvmExecutor, ParallelEvmConfig,
};
use tokio::sync::mpsc;

/// The engine node launcher.
#[derive(Debug)]
pub struct PEvmNodeLauncher {
    /// Reth node launcher
    node_launcher: EngineNodeLauncher,
    config: NodeConfig<ChainSpec>,
    thread_count: usize,
    rx_execution_request: mpsc::UnboundedReceiver<BlockExecutionRequest>,
    /// The task executor for the node.
    ctx: LaunchContext,
}

impl PEvmNodeLauncher {
    /// Create a new instance of the ethereum node launcher.
    pub fn new(
        task_executor: TaskExecutor,
        config: &NodeConfig<ChainSpec>,
        thread_count: usize,
        rx_execution_request: mpsc::UnboundedReceiver<BlockExecutionRequest>,
        engine_tree_config: TreeConfig,
    ) -> Self {
        let ctx = LaunchContext::new(task_executor.clone(), config.datadir());
        let node_launcher =
            EngineNodeLauncher::new(task_executor, config.datadir(), engine_tree_config);
        Self { node_launcher, config: config.clone(), thread_count, rx_execution_request, ctx }
    }
}

impl<Types, T, CB, AO> LaunchNode<NodeBuilderWithComponents<T, CB, AO>> for PEvmNodeLauncher
where
    Types: ProviderNodeTypes + NodeTypesWithEngine,
    T: FullNodeTypes<Types = Types, Provider = BlockchainProvider2<Types>>,
    CB: NodeComponentsBuilder<T>,
    AO: NodeAddOns<
        NodeAdapter<T, CB::Components>,
        EthApi: EthApiBuilderProvider<NodeAdapter<T, CB::Components>>
                    + FullEthApiServer
                    + AddDevSigners,
    >,
{
    type Node = NodeHandle<NodeAdapter<T, CB::Components>, AO>;
    //Launch an executor thread with miltiple worker evm execution threads
    async fn launch_node(
        self,
        target: NodeBuilderWithComponents<T, CB, AO>,
    ) -> eyre::Result<Self::Node> {
        let PEvmNodeLauncher { node_launcher, config, thread_count, rx_execution_request, ctx } =
            self;
        let task_executor = ctx.task_executor.clone();
        let chain_spec = config.chain.clone();
        let chain = Arc::new(PevmEthereum::new(chain_spec.chain.id()));
        let evm_config = ParallelEvmConfig::new(chain_spec.clone());
        task_executor.spawn(Box::pin(async move {
            let mut evm_executor =
                ParallelEthEvmExecutor::new(chain_spec, chain, evm_config, rx_execution_request);
            evm_executor.start(thread_count).await;
        }));
        node_launcher.launch_node(target).await
    }
}
