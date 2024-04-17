use p3_field::{AbstractField, Field};
use wp1_derive::AlignedBorrow;

use crate::{
    air::{SP1AirBuilder, Word},
    bytes::ByteOpcode,
    disassembler::WORD_SIZE,
    runtime::ExecutionRecord,
};

/// A set of columns needed to compute the or of two words.
///
/// TODO: This is currently not in use, and thus not tested thoroughly yet.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct OrOperation<T> {
    /// The result of `x | y`.
    pub value: Word<T>,
}

impl<F: Field> OrOperation<F> {
    pub fn populate(&mut self, record: &mut ExecutionRecord, shard: u32, x: u32, y: u32) -> u32 {
        let expected = x | y;
        let x_bytes = x.to_le_bytes();
        let y_bytes = y.to_le_bytes();
        for i in 0..WORD_SIZE {
            self.value[i] = F::from_canonical_u8(x_bytes[i] | y_bytes[i]);
            record.lookup_or(shard, x_bytes[i], y_bytes[i]);
        }
        expected
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: OrOperation<AB::Var>,
        shard: AB::Var,
        is_real: AB::Var,
    ) {
        for i in 0..WORD_SIZE {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::OR as u32),
                cols.value[i],
                a[i],
                b[i],
                shard,
                is_real,
            );
        }
    }
}
