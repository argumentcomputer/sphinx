use wp1_derive::AlignedBorrow;

use crate::air::Block;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AluCols<T> {
    pub ext_a: Block<T>,

    pub ext_b: Block<T>,

    pub ext_c: Block<T>,

    // Used for field and extension div operations.
    pub inverse_scratch: Block<T>,
}
