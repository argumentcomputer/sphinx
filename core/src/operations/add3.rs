use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use sphinx_derive::AlignedBorrow;

use crate::air::Word;
use crate::air::WordAirBuilder;
use crate::air::WORD_SIZE;
use crate::bytes::event::ByteRecord;

/// A set of columns needed to compute the add of three words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Add3Operation<T> {
    /// The result of `a + b + c`.
    pub value: Word<T>,

    /// Indicates if the carry for the `i`th digit is 0.
    pub is_carry_0: Word<T>,

    /// Indicates if the carry for the `i`th digit is 1.
    pub is_carry_1: Word<T>,

    /// Indicates if the carry for the `i`th digit is 2. The carry when adding 3 words is at most 2.
    pub is_carry_2: Word<T>,

    /// The carry for the `i`th digit.
    pub carry: Word<T>,
}

impl<F: Field> Add3Operation<F> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        shard: u32,
        channel: u32,
        a_u32: u32,
        b_u32: u32,
        c_u32: u32,
    ) -> u32 {
        let expected = a_u32.wrapping_add(b_u32).wrapping_add(c_u32);

        self.value = Word::from(expected);
        let a = a_u32.to_le_bytes();
        let b = b_u32.to_le_bytes();
        let c = c_u32.to_le_bytes();

        let base = 256;
        let mut carry = [0u8, 0u8, 0u8, 0u8];
        for i in 0..WORD_SIZE {
            let mut res = u32::from(a[i]) + u32::from(b[i]) + u32::from(c[i]);
            if i > 0 {
                res += u32::from(carry[i - 1]);
            }
            carry[i] = (res / base) as u8;
            self.is_carry_0[i] = F::from_bool(carry[i] == 0);
            self.is_carry_1[i] = F::from_bool(carry[i] == 1);
            self.is_carry_2[i] = F::from_bool(carry[i] == 2);
            self.carry[i] = F::from_canonical_u8(carry[i]);
            debug_assert!(carry[i] <= 2);
            debug_assert_eq!(self.value[i], F::from_canonical_u32(res % base));
        }

        // Range check.
        {
            record.add_u8_range_checks(shard, channel, &a);
            record.add_u8_range_checks(shard, channel, &b);
            record.add_u8_range_checks(shard, channel, &c);
            record.add_u8_range_checks(shard, channel, &expected.to_le_bytes());
        }
        expected
    }

    pub fn eval<AB: WordAirBuilder<F = F>>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        c: Word<AB::Var>,
        shard: AB::Var,
        channel: impl Into<AB::Expr> + Copy,
        is_real: AB::Var,
        cols: Add3Operation<AB::Var>,
    ) {
        // Range check each byte.
        {
            builder.slice_range_check_u8(&a.0, shard, channel, is_real);
            builder.slice_range_check_u8(&b.0, shard, channel, is_real);
            builder.slice_range_check_u8(&c.0, shard, channel, is_real);
            builder.slice_range_check_u8(&cols.value.0, shard, channel, is_real);
        }

        builder.assert_bool(is_real);
        let mut builder_is_real = builder.when(is_real);

        // Each value in is_carry_{0,1,2,3} is 0 or 1, and exactly one of them is 1 per digit.
        {
            for i in 0..WORD_SIZE {
                builder_is_real.assert_bool(cols.is_carry_0[i]);
                builder_is_real.assert_bool(cols.is_carry_1[i]);
                builder_is_real.assert_bool(cols.is_carry_2[i]);
                builder_is_real.assert_eq(
                    cols.is_carry_0[i] + cols.is_carry_1[i] + cols.is_carry_2[i],
                    AB::Expr::one(),
                );
            }
        }

        // Calculates carry from is_carry_{0,1,2}.
        {
            let one = AB::Expr::one();
            let two = AB::F::from_canonical_u32(2);

            for i in 0..WORD_SIZE {
                builder_is_real.assert_eq(
                    cols.carry[i],
                    cols.is_carry_1[i] * one.clone() + cols.is_carry_2[i] * two,
                );
            }
        }

        // Compare the sum and summands by looking at carry.
        {
            let base = AB::F::from_canonical_u32(256);
            // For each limb, assert that difference between the carried result and the non-carried
            // result is the product of carry and base.
            for i in 0..WORD_SIZE {
                let mut overflow = a[i] + b[i] + c[i] - cols.value[i];
                if i > 0 {
                    overflow += cols.carry[i - 1].into();
                }
                builder_is_real.assert_eq(cols.carry[i] * base, overflow.clone());
            }
        }
    }
}
