use std::mem::size_of;

use sphinx_derive::AlignedBorrow;

use crate::{
    memory::{MemoryReadCols, MemoryWriteCols},
    operations::{
        Add64Operation, And64Operation, FixedRotateRight64Operation, Not64Operation, Xor64Operation,
    },
};

pub(crate) const NUM_SHA512_COMPRESS_COLS: usize = size_of::<Sha512CompressCols<u8>>();

/// A set of columns needed to compute the SHA-512 compression function.
///
/// Each sha512 compress syscall is processed over 80 columns, split into 10 octets. The first octet is
/// for initialization, the next 8 octets are for compression, and the last octet is for finalize.
/// During init, the columns are initialized with the input values, one word at a time. During each
/// compression cycle, one iteration of sha512 compress is computed. During finalize, the columns are
/// combined and written back to memory.
/// FIXME
#[derive(AlignedBorrow, Default, Debug, Clone)]
#[repr(C)]
pub struct Sha512CompressCols<T> {
    /// Inputs.
    pub shard: T,
    pub channel: T,
    pub nonce: T,
    pub clk: T,
    pub w_ptr: T,
    pub h_ptr: T,

    pub i_mem: MemoryWriteCols<T>,
    pub i: T,
    pub w_i: [MemoryReadCols<T>; 2],
    pub k_i: [MemoryReadCols<T>; 2],

    pub h: [MemoryWriteCols<T>; 16],

    pub e_rr_14: FixedRotateRight64Operation<T>,
    pub e_rr_18: FixedRotateRight64Operation<T>,
    pub e_rr_41: FixedRotateRight64Operation<T>,
    pub s1_intermediate: Xor64Operation<T>,
    /// `S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)`.
    pub s1: Xor64Operation<T>,

    pub e_and_f: And64Operation<T>,
    pub e_not: Not64Operation<T>,
    pub e_not_and_g: And64Operation<T>,
    /// `ch := (e and f) xor ((not e) and g)`.
    pub ch: Xor64Operation<T>,

    /// `temp1 := h + S1 + ch + k[i] + w[i]`.
    pub temp1: [Add64Operation<T>; 4],

    pub a_rr_28: FixedRotateRight64Operation<T>,
    pub a_rr_34: FixedRotateRight64Operation<T>,
    pub a_rr_39: FixedRotateRight64Operation<T>,
    pub s0_intermediate: Xor64Operation<T>,
    /// `S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)`.
    pub s0: Xor64Operation<T>,

    pub a_and_b: And64Operation<T>,
    pub a_and_c: And64Operation<T>,
    pub b_and_c: And64Operation<T>,
    pub maj_intermediate: Xor64Operation<T>,
    /// `maj := (a and b) xor (a and c) xor (b and c)`.
    pub maj: Xor64Operation<T>,

    /// `temp2 := S0 + maj`.
    pub temp2: Add64Operation<T>,

    /// The next value of `e` is `d + temp1`.
    pub d_add_temp1: Add64Operation<T>,
    /// The next value of `a` is `temp1 + temp2`.
    pub temp1_add_temp2: Add64Operation<T>,

    pub is_real: T,
}
