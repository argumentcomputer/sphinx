use std::mem::size_of;

use sphinx_derive::AlignedBorrow;

use crate::{
    memory::{MemoryReadCols, MemoryWriteCols},
    operations::{
        Add64Operation, FixedRotateRight64Operation, FixedShiftRight64Operation, Xor64Operation,
    },
};

pub const NUM_SHA512_EXTEND_COLS: usize = size_of::<Sha512ExtendCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone)]
#[repr(C)]
pub struct Sha512ExtendCols<T> {
    /// Inputs.
    pub shard: T,
    pub channel: T,
    pub nonce: T,
    pub clk: T,
    pub w_ptr: T,
    pub i: T,

    /// Inputs to `s0`.
    pub w_i_minus_15: [MemoryReadCols<T>; 2],
    pub w_i_minus_15_rr_1: FixedRotateRight64Operation<T>,
    pub w_i_minus_15_rr_8: FixedRotateRight64Operation<T>,
    pub w_i_minus_15_rs_7: FixedShiftRight64Operation<T>,
    pub s0_intermediate: Xor64Operation<T>,

    /// `s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)`
    pub s0: Xor64Operation<T>,

    /// Inputs to `s1`.
    pub w_i_minus_2: [MemoryReadCols<T>; 2],
    pub w_i_minus_2_rr_19: FixedRotateRight64Operation<T>,
    pub w_i_minus_2_rr_61: FixedRotateRight64Operation<T>,
    pub w_i_minus_2_rs_6: FixedShiftRight64Operation<T>,
    pub s1_intermediate: Xor64Operation<T>,

    /// `s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)`
    pub s1: Xor64Operation<T>,

    /// Inputs to `s2`.
    pub w_i_minus_16: [MemoryReadCols<T>; 2],
    pub w_i_minus_7: [MemoryReadCols<T>; 2],

    /// `w[i] := w[i-16] + s0 + w[i-7] + s1`.
    pub s2: [Add64Operation<T>; 3],

    /// Result.
    pub w_i: [MemoryWriteCols<T>; 2],

    /// Selector.
    pub is_real: T,
}
