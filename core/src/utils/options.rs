#[derive(Debug, Clone, Copy)]
pub struct SphinxCoreOpts {
    pub shard_size: usize,
    pub shard_batch_size: usize,
    pub shard_chunking_multiplier: usize,
    pub reconstruct_commitments: bool,
}

impl Default for SphinxCoreOpts {
    fn default() -> Self {
        Self {
            shard_size: 1 << 22,
            shard_batch_size: 16,
            shard_chunking_multiplier: 1,
            reconstruct_commitments: false,
        }
    }
}

impl SphinxCoreOpts {
    pub fn recursion() -> Self {
        let mut opts = Self::default();
        opts.reconstruct_commitments = false;
        opts
    }
}
