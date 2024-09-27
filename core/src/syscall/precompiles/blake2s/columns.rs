use crate::memory::{MemoryReadCols, MemoryWriteCols};
use crate::operations::{Add3Operation, AddOperation, FixedRotateRightOperation, XorOperation};
use sphinx_derive::AlignedBorrow;

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Blake2sRoundCols<T> {
    /// Inputs.
    pub clk: T,
    pub shard: T,
    pub channel: T,
    pub nonce: T,
    pub is_real: T,

    pub a_ptr: T,
    pub b_ptr: T,

    /// Memory layout:
    /// a: v0[0] || v0[1] || v0[2] || v0[3] ||
    ///    v1[0] || v1[1] || v1[2] || v1[3] ||
    ///    v2[0] || v2[1] || v2[2] || v2[3] ||
    ///    v3[0] || v3[1] || v3[2] || v3[3] ||
    ///
    /// b: m0[0] || m0[1] || m0[2] || m0[3] ||
    ///    m1[0] || m1[1] || m1[2] || m1[3] ||
    ///    m2[0] || m2[1] || m2[2] || m2[3] ||
    ///    m3[0] || m3[1] || m3[2] || m3[3] ||
    ///
    pub a: [MemoryWriteCols<T>; 16],
    pub b: [MemoryReadCols<T>; 16],

    pub add3: [Add3Operation<T>; 16],
    pub add2: [AddOperation<T>; 16],
    pub xor: [XorOperation<T>; 32],
    pub rotate_right: [FixedRotateRightOperation<T>; 32],
}
