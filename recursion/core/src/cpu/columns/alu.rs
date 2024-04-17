use wp1_derive::AlignedBorrow;

use crate::air::Block;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AluCols<T> {
    pub ext_a: Block<T>,

    pub ext_b: Block<T>,

    // c = a + b;
    pub add_scratch: Block<T>,

    // c = a - b;
    pub sub_scratch: Block<T>,

    // c = a * b;
    pub mul_scratch: Block<T>,
}
