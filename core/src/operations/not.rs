use p3_air::AirBuilder;
use p3_field::Field;
use wp1_derive::AlignedBorrow;

use crate::air::SP1AirBuilder;
use crate::air::Word;
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteOpcode;
use crate::disassembler::WORD_SIZE;
use crate::runtime::ExecutionRecord;

/// A set of columns needed to compute the not of a word.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct NotOperation<T> {
    /// The result of `!x`.
    pub value: Word<T>,
}

impl<F: Field> NotOperation<F> {
    pub fn populate(&mut self, record: &mut ExecutionRecord, shard: u32, x: u32) -> u32 {
        let expected = !x;
        let x_bytes = x.to_le_bytes();
        for i in 0..WORD_SIZE {
            self.value[i] = F::from_canonical_u8(!x_bytes[i]);
        }
        record.add_u8_range_checks(shard, &x_bytes);
        expected
    }

    pub fn eval<AB: SP1AirBuilder<F = F>>(
        builder: &mut AB,
        a: Word<AB::Var>,
        cols: NotOperation<AB::Var>,
        shard: AB::Var,
        is_real: AB::Var,
    ) {
        for i in (0..WORD_SIZE).step_by(2) {
            builder.send_byte_pair(
                AB::F::from_canonical_u32(ByteOpcode::U8Range as u32),
                AB::F::zero(),
                AB::F::zero(),
                a[i],
                a[i + 1],
                shard,
                is_real,
            );
        }

        // For any byte b, b + !b = 0xFF.
        for i in 0..WORD_SIZE {
            builder
                .when(is_real)
                .assert_eq(cols.value[i] + a[i], AB::F::from_canonical_u8(u8::MAX));
        }

        // A dummy constraint to keep the degree 3.
        #[allow(clippy::eq_op)]
        builder.assert_zero(a[0] * a[0] * a[0] - a[0] * a[0] * a[0]);
    }
}
