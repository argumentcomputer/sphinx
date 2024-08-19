use crate::air::{Word64, WordAirBuilder, WORD64_SIZE};
use crate::bytes::event::ByteRecord;

use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use sphinx_derive::AlignedBorrow;

/// A set of columns needed to compute the add of two double words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Add64Operation<T> {
    /// The result of `a + b`.
    pub value: Word64<T>,

    /// Trace.
    pub carry: [T; WORD64_SIZE - 1],
}

impl<F: Field> Add64Operation<F> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        shard: u32,
        channel: u32,
        a_u64: u64,
        b_u64: u64,
    ) -> u64 {
        let expected = a_u64.wrapping_add(b_u64);
        self.value = Word64::from(expected);
        let a = a_u64.to_le_bytes();
        let b = b_u64.to_le_bytes();

        let mut carry = [0u8; WORD64_SIZE - 1];
        if u64::from(a[0]) + u64::from(b[0]) > 255 {
            carry[0] = 1;
            self.carry[0] = F::one();
        }
        for i in 1..WORD64_SIZE {
            if u64::from(a[i]) + u64::from(b[i]) + u64::from(carry[i - 1]) > 255 {
                carry[i] = 1;
                self.carry[i] = F::one();
            }
        }

        let base = 256u64;
        let overflow = u64::from(
            a[0].wrapping_add(b[0])
                .wrapping_sub(expected.to_le_bytes()[0]),
        );
        debug_assert_eq!(overflow.wrapping_mul(overflow.wrapping_sub(base)), 0);

        // Range check
        {
            record.add_u8_range_checks(shard, channel, &a);
            record.add_u8_range_checks(shard, channel, &b);
            record.add_u8_range_checks(shard, channel, &expected.to_le_bytes());
        }
        expected
    }

    pub fn eval<AB: WordAirBuilder<F = F>>(
        builder: &mut AB,
        a: Word64<AB::Var>,
        b: Word64<AB::Var>,
        cols: Add64Operation<AB::Var>,
        shard: AB::Var,
        channel: impl Into<AB::Expr> + Clone,
        is_real: AB::Expr,
    ) {
        let one = AB::Expr::one();
        let base = AB::F::from_canonical_u32(256);

        let mut builder_is_real = builder.when(is_real.clone());

        // For each limb, assert that difference between the carried result and the non-carried
        // result is either zero or the base.
        let overflow_0 = a[0] + b[0] - cols.value[0];
        let overflow_1 = a[1] + b[1] - cols.value[1] + cols.carry[0];
        let overflow_2 = a[2] + b[2] - cols.value[2] + cols.carry[1];
        let overflow_3 = a[3] + b[3] - cols.value[3] + cols.carry[2];
        let overflow_4 = a[4] + b[4] - cols.value[4] + cols.carry[3];
        let overflow_5 = a[5] + b[5] - cols.value[5] + cols.carry[4];
        let overflow_6 = a[6] + b[6] - cols.value[6] + cols.carry[5];
        let overflow_7 = a[7] + b[7] - cols.value[7] + cols.carry[6];
        builder_is_real.assert_zero(overflow_0.clone() * (overflow_0.clone() - base));
        builder_is_real.assert_zero(overflow_1.clone() * (overflow_1.clone() - base));
        builder_is_real.assert_zero(overflow_2.clone() * (overflow_2.clone() - base));
        builder_is_real.assert_zero(overflow_3.clone() * (overflow_3.clone() - base));
        builder_is_real.assert_zero(overflow_4.clone() * (overflow_4.clone() - base));
        builder_is_real.assert_zero(overflow_5.clone() * (overflow_5.clone() - base));
        builder_is_real.assert_zero(overflow_6.clone() * (overflow_6.clone() - base));
        builder_is_real.assert_zero(overflow_7.clone() * (overflow_7.clone() - base));

        // If the carry is one, then the overflow must be the base.
        builder_is_real.assert_zero(cols.carry[0] * (overflow_0.clone() - base));
        builder_is_real.assert_zero(cols.carry[1] * (overflow_1.clone() - base));
        builder_is_real.assert_zero(cols.carry[2] * (overflow_2.clone() - base));
        builder_is_real.assert_zero(cols.carry[3] * (overflow_3.clone() - base));
        builder_is_real.assert_zero(cols.carry[4] * (overflow_4.clone() - base));
        builder_is_real.assert_zero(cols.carry[5] * (overflow_5.clone() - base));
        builder_is_real.assert_zero(cols.carry[6] * (overflow_6.clone() - base));

        // If the carry is not one, then the overflow must be zero.
        builder_is_real.assert_zero((cols.carry[0] - one.clone()) * overflow_0.clone());
        builder_is_real.assert_zero((cols.carry[1] - one.clone()) * overflow_1.clone());
        builder_is_real.assert_zero((cols.carry[2] - one.clone()) * overflow_2.clone());
        builder_is_real.assert_zero((cols.carry[3] - one.clone()) * overflow_3.clone());
        builder_is_real.assert_zero((cols.carry[4] - one.clone()) * overflow_4.clone());
        builder_is_real.assert_zero((cols.carry[5] - one.clone()) * overflow_5.clone());
        builder_is_real.assert_zero((cols.carry[6] - one.clone()) * overflow_6.clone());

        // Assert that the carry is either zero or one.
        builder_is_real.assert_bool(cols.carry[0]);
        builder_is_real.assert_bool(cols.carry[1]);
        builder_is_real.assert_bool(cols.carry[2]);
        builder_is_real.assert_bool(cols.carry[3]);
        builder_is_real.assert_bool(cols.carry[4]);
        builder_is_real.assert_bool(cols.carry[5]);
        builder_is_real.assert_bool(cols.carry[6]);
        builder_is_real.assert_bool(is_real.clone());

        // Range check each byte.
        {
            builder.slice_range_check_u8(&a.0, shard, channel.clone(), is_real.clone());
            builder.slice_range_check_u8(&b.0, shard, channel.clone(), is_real.clone());
            builder.slice_range_check_u8(&cols.value.0, shard, channel, is_real);
        }
    }
}
