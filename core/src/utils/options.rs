use std::env;

use crate::runtime::{SplitOpts, DEFERRED_SPLIT_THRESHOLD};

const DEFAULT_SHARD_SIZE: usize = 1 << 22;
const DEFAULT_SHARD_BATCH_SIZE: usize = 16;
const DEFAULT_COMMIT_STREAM_CAPACITY: usize = 1;
const DEFAULT_PROVE_STREAM_CAPACITY: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SphinxProverOpts {
    pub core_opts: SphinxCoreOpts,
    pub recursion_opts: SphinxCoreOpts,
}

impl Default for SphinxProverOpts {
    fn default() -> Self {
        Self {
            core_opts: SphinxCoreOpts::default(),
            recursion_opts: SphinxCoreOpts::recursion(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SphinxCoreOpts {
    pub shard_size: usize,
    pub shard_batch_size: usize,
    pub commit_stream_capacity: usize,
    pub prove_stream_capacity: usize,
    pub split_opts: SplitOpts,
    pub reconstruct_commitments: bool,
}

impl Default for SphinxCoreOpts {
    fn default() -> Self {
        let split_threshold = env::var("SPLIT_THRESHOLD")
            .map(|s| s.parse::<usize>().unwrap_or(DEFERRED_SPLIT_THRESHOLD))
            .unwrap_or(DEFERRED_SPLIT_THRESHOLD);
        Self {
            shard_size: env::var("SHARD_SIZE").map_or_else(
                |_| DEFAULT_SHARD_SIZE,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_SHARD_SIZE),
            ),
            shard_batch_size: env::var("SHARD_BATCH_SIZE").map_or_else(
                |_| DEFAULT_SHARD_BATCH_SIZE,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_SHARD_BATCH_SIZE),
            ),
            commit_stream_capacity: env::var("COMMIT_STREAM_CAPACITY").map_or_else(
                |_| DEFAULT_COMMIT_STREAM_CAPACITY,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_COMMIT_STREAM_CAPACITY),
            ),
            prove_stream_capacity: env::var("PROVE_STREAM_CAPACITY").map_or_else(
                |_| DEFAULT_PROVE_STREAM_CAPACITY,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_PROVE_STREAM_CAPACITY),
            ),
            split_opts: SplitOpts::new(split_threshold),
            reconstruct_commitments: true,
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
