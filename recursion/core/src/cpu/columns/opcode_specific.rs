use std::fmt::{Debug, Formatter};
use std::mem::{size_of, transmute};

pub(crate) const NUM_OPCODE_SPECIFIC_COLS: usize = size_of::<OpcodeSpecificCols<u8>>();

/// Shared columns whose interpretation depends on the instruction being executed.
/// TODO: Remove this struct if we end up not needed any opcode-specific columns.
#[derive(Clone, Copy)]
#[repr(C)]
pub union OpcodeSpecificCols<T: Copy> {
    dummy: T,
}

impl<T: Copy + Default> Default for OpcodeSpecificCols<T> {
    fn default() -> Self {
        OpcodeSpecificCols {
            dummy: Default::default(),
        }
    }
}

impl<T: Copy + Debug> Debug for OpcodeSpecificCols<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // SAFETY: repr(C) ensures uniform fields are in declaration order with no padding.
        let self_arr: &[T; NUM_OPCODE_SPECIFIC_COLS] = unsafe { transmute(self) };
        Debug::fmt(self_arr, f)
    }
}
