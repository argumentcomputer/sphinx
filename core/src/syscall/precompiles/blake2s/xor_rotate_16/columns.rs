use std::mem::size_of;

use sphinx_derive::AlignedBorrow;

use crate::{
    memory::{MemoryReadCols, MemoryWriteCols},
    operations::{FixedRotateRightOperation, IsZeroOperation, XorOperation},
};

pub const NUM_BLAKE2S_XOR_ROTATE_16_COLS: usize = size_of::<Blake2sXorRotate16Cols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Blake2sXorRotate16Cols<T> {
    /// Inputs.
    pub shard: T,
    pub channel: T,
    pub nonce: T,
    pub clk: T,
    pub w_ptr: T,

    /// Control flags.
    pub i: T,

    /// g^n where g is generator with order 16 and n is the row number.
    pub cycle_16: T,

    /// Checks whether current row is start of a 16-row cycle. Bool result is stored in `result`.
    pub cycle_16_start: IsZeroOperation<T>,

    /// Checks whether current row is end of a 16-row cycle. Bool result is stored in `result`.
    pub cycle_16_end: IsZeroOperation<T>,

    /// Flags for when in the first, second, or third 16-row cycle.
    pub cycle_48: [T; 3],

    /// Whether the current row is the first of a 48-row cycle and is real.
    pub cycle_48_start: T,
    /// Whether the current row is the end of a 48-row cycle and is real.
    pub cycle_48_end: T,

    /// Inputs
    pub w_0: MemoryReadCols<T>,
    pub w_1: MemoryReadCols<T>,
    pub w_2: MemoryReadCols<T>,
    pub w_3: MemoryReadCols<T>,
    pub w_4: MemoryReadCols<T>,
    pub w_5: MemoryReadCols<T>,
    pub w_6: MemoryReadCols<T>,
    pub w_7: MemoryReadCols<T>,

    /// Operations
    pub xor_0: XorOperation<T>,
    pub xor_1: XorOperation<T>,
    pub xor_2: XorOperation<T>,
    pub xor_3: XorOperation<T>,

    pub rot_0: FixedRotateRightOperation<T>,
    pub rot_1: FixedRotateRightOperation<T>,
    pub rot_2: FixedRotateRightOperation<T>,
    pub rot_3: FixedRotateRightOperation<T>,

    /// Result
    pub w_16: MemoryWriteCols<T>,
    pub w_17: MemoryWriteCols<T>,
    pub w_18: MemoryWriteCols<T>,
    pub w_19: MemoryWriteCols<T>,

    /// Selector.
    pub is_real: T,
}
