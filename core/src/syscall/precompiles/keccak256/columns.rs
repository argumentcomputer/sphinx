use core::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::memory::MemoryReadWriteCols;

use super::STATE_NUM_WORDS;

#[derive(AlignedBorrow)]
#[repr(C)]
pub(crate) struct KeccakMemCols<T> {
    pub(crate) shard: T,
    pub(crate) clk: T,

    pub(crate) state_mem: [MemoryReadWriteCols<T>; STATE_NUM_WORDS],
    pub(crate) state_addr: T,

    pub do_memory_check: T,
    pub ecall_receive: T,

    pub(crate) is_real: T,
}

pub const NUM_KECCAK_MEM_COLS: usize = size_of::<KeccakMemCols<u8>>();
