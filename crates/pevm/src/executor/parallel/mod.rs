pub mod chain;
pub mod context;
mod eth_batch_executor;
mod eth_block_executor;
mod eth_evm_executor;
mod evm;
mod memory;
mod scheduler;
/// Storage traits for the parallel executor.
pub mod storage;
/// Types used in the parallel executor.
pub mod types;
use core::{cell::LazyCell, num::NonZeroUsize};
use std::thread;

pub use context::ParallelEvmContext;
pub(crate) use eth_batch_executor::ParallelEthBatchExecutor;
pub(crate) use eth_block_executor::ParallelEthBlockExecutor;
pub use eth_evm_executor::ParallelEthEvmExecutor;
use reth_evm::execute::ProviderError;
use revm::{Database, State};

pub(crate) use scheduler::Scheduler;
//pub type StateBox<'a> = StateDBBox<'a, ProviderError>;

pub type DBBox<E> = Box<dyn Database<Error = E> + Send>;

/// More constrained version of State that uses Boxed database with a lifetime.
///
/// This is used to make it easier to use State.
pub type StateDBBox = State<DBBox<ProviderError>>;

/// The default number of executors to use for parallel execution.
pub const DEFAULT_EXECUTORS: LazyCell<NonZeroUsize> = LazyCell::new(|| {
    thread::available_parallelism().unwrap_or(NonZeroUsize::MIN).min(
        NonZeroUsize::new(
            #[cfg(target_arch = "aarch64")]
            12,
            #[cfg(not(target_arch = "aarch64"))]
            8,
        )
        .unwrap(),
    )
});
