//! This example shows how to implement a node with a custom EVM

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
mod builder;
use builder::*;
use clap::{Args, Parser};
use reth::cli::Cli;
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_node_builder::{
    engine_tree_config::{
        TreeConfig, DEFAULT_MEMORY_BLOCK_BUFFER_TARGET, DEFAULT_PERSISTENCE_THRESHOLD,
    },
    EngineNodeLauncher,
};

use reth_tracing::{RethTracer, Tracer};
use scalar_node::{
    node::{ScalarNode, ScalarNodeAddOns},
    ScalarChainProvider,
};
/// Parameters for configuring the engine
#[derive(Debug, Clone, Args, PartialEq, Eq)]
#[command(next_help_heading = "Engine")]
pub struct EngineArgs {
    /// Enable the engine2 experimental features on reth binary
    #[arg(long = "engine.experimental", default_value = "false")]
    pub experimental: bool,

    /// Configure persistence threshold for engine experimental.
    #[arg(long = "engine.persistence-threshold", requires = "experimental", default_value_t = DEFAULT_PERSISTENCE_THRESHOLD)]
    pub persistence_threshold: u64,

    /// Configure the target number of blocks to keep in memory.
    #[arg(long = "engine.memory-block-buffer-target", requires = "experimental", default_value_t = DEFAULT_MEMORY_BLOCK_BUFFER_TARGET)]
    pub memory_block_buffer_target: u64,
}

impl Default for EngineArgs {
    fn default() -> Self {
        Self {
            experimental: false,
            persistence_threshold: DEFAULT_PERSISTENCE_THRESHOLD,
            memory_block_buffer_target: DEFAULT_MEMORY_BLOCK_BUFFER_TARGET,
        }
    }
}

//#[tokio::main]
fn main() -> eyre::Result<()> {
    let _guard = RethTracer::new().init();
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    let res = Cli::<EthereumChainSpecParser, EngineArgs>::parse().run(
        |builder, engine_args| async move {
            let enable_engine2 = engine_args.experimental;
            match enable_engine2 {
                true => {
                    println!("Starting reth with engine2");
                    let engine_tree_config = TreeConfig::default()
                        .with_persistence_threshold(engine_args.persistence_threshold)
                        .with_memory_block_buffer_target(engine_args.memory_block_buffer_target);
                    let handle = builder
                        .with_types_and_provider::<ScalarNode, ScalarChainProvider<_>>()
                        .with_components(
                            ScalarNode::components()
                                .executor(ParallelExecutorBuilder::default())
                                .payload(ScalarPayloadBuilder::default()),
                        )
                        .with_add_ons(ScalarNodeAddOns::default())
                        .launch_with_fn(|builder| {
                            let launcher = EngineNodeLauncher::new(
                                builder.task_executor().clone(),
                                builder.config().datadir(),
                                engine_tree_config,
                            );
                            builder.launch_with(launcher)
                        })
                        .await?;
                    handle.node_exit_future.await
                }
                false => {
                    println!("Starting reth with default engine");
                    let handle = builder.launch_node(ScalarNode::default()).await?;
                    handle.node_exit_future.await
                }
            }
        },
    );
    if let Err(err) = res {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A helper type to parse Args more easily
    #[derive(Parser)]
    struct CommandParser<T: Args> {
        #[command(flatten)]
        args: T,
    }

    #[test]
    fn test_parse_engine_args() {
        let default_args = EngineArgs::default();
        let args = CommandParser::<EngineArgs>::parse_from(["reth"]).args;
        assert_eq!(args, default_args);
    }
}
