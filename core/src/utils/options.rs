use std::env;

const DEFAULT_SHARD_SIZE: usize = 1 << 22;
const DEFAULT_SHARD_BATCH_SIZE: usize = 16;
const DEFAULT_SHARD_CHUNKING_MULTIPLIER: usize = 1;
const DEFAULT_RECONSTRUCT_COMMITMENTS: bool = true;

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
            shard_size: env::var("SHARD_SIZE").map_or_else(
                |_| DEFAULT_SHARD_SIZE,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_SHARD_SIZE),
            ),
            shard_batch_size: env::var("SHARD_BATCH_SIZE").map_or_else(
                |_| DEFAULT_SHARD_BATCH_SIZE,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_SHARD_BATCH_SIZE),
            ),
            shard_chunking_multiplier: env::var("SHARD_CHUNKING_MULTIPLIER").map_or_else(
                |_| DEFAULT_SHARD_CHUNKING_MULTIPLIER,
                |s| {
                    s.parse::<usize>()
                        .unwrap_or(DEFAULT_SHARD_CHUNKING_MULTIPLIER)
                },
            ),
            reconstruct_commitments: env::var("RECONSTRUCT_COMMITMENTS").map_or_else(
                |_| DEFAULT_RECONSTRUCT_COMMITMENTS,
                |s| s.parse::<bool>().unwrap_or(DEFAULT_RECONSTRUCT_COMMITMENTS),
            ),
        }
    }
}

impl SphinxCoreOpts {
    pub fn recursion() -> Self {
        let mut opts = Self::default();
        opts.reconstruct_commitments = false;
        opts.shard_size = DEFAULT_SHARD_SIZE;
        opts
    }
}
