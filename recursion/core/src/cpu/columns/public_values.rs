use std::mem::size_of;
use sphinx_derive::AlignedBorrow;

use crate::runtime::DIGEST_SIZE;

#[allow(dead_code)]
pub(crate) const NUM_PUBLIC_VALUES_COLS: usize = size_of::<PublicValuesCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct PublicValuesCols<T> {
    pub(crate) idx_bitmap: [T; DIGEST_SIZE],
}
