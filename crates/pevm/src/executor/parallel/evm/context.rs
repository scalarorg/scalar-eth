use reth_primitives::{BlockWithSenders, TxType};
use revm_primitives::{BlockEnv, SpecId, TxEnv};

/// Store block information for each block.
/// This context is shared between all EVMWrapper.
#[derive(Debug, Clone)]
pub(crate) struct BlockContext {
    pub(crate) block: BlockWithSenders,
    pub(crate) txs: Vec<(TxEnv, TxType)>,
    pub(crate) spec_id: SpecId,
    pub(crate) block_env: BlockEnv,
}

impl BlockContext {
    pub(crate) fn new(
        block: BlockWithSenders,
        txs: Vec<(TxEnv, TxType)>,
        spec_id: SpecId,
        block_env: BlockEnv,
    ) -> Self {
        Self { block, txs, spec_id, block_env }
    }
}

impl BlockContext {
    pub(crate) fn get_tx(&self, idx: usize) -> Option<(&TxEnv, &TxType)> {
        self.txs.get(idx).map(|(tx_env, tx_type)| (tx_env, tx_type))
    }
}
