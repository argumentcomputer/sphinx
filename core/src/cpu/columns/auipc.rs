use std::mem::size_of;

use sphinx_derive::AlignedBorrow;

use crate::{air::Word, operations::BabyBearWordRangeChecker};

pub const NUM_AUIPC_COLS: usize = size_of::<AuipcCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AuipcCols<T> {
    /// The current program counter.
    pub pc: Word<T>,
    pub pc_range_checker: BabyBearWordRangeChecker<T>,
    pub auipc_nonce: T,
}
