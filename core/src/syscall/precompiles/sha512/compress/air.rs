use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;

use super::{
    columns::{Sha512CompressCols, NUM_SHA512_COMPRESS_COLS},
    Sha512CompressChip,
};
use crate::{
    air::{
        AluAirBuilder, BaseAirBuilder, ByteAirBuilder, MemoryAirBuilder, Word64, WordAirBuilder,
    },
    bytes::ByteOpcode,
    memory::MemoryCols,
    operations::{
        Add64Operation, And64Operation, FixedRotateRight64Operation, Not64Operation, Xor64Operation,
    },
    runtime::SyscallCode,
};

impl<F> BaseAir<F> for Sha512CompressChip {
    fn width(&self) -> usize {
        NUM_SHA512_COMPRESS_COLS
    }
}

impl<AB> Air<AB> for Sha512CompressChip
where
    AB: BaseAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &Sha512CompressCols<AB::Var> = (*local).borrow();
        let next: &Sha512CompressCols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // Assert that is_real is a bool.
        builder.assert_bool(local.is_real);

        self.eval_memory(builder, local);

        self.eval_compression_ops(builder, local);

        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::SHA512_COMPRESS.syscall_id()),
            local.w_ptr,
            local.h_ptr,
            local.is_real,
        );
    }
}

impl Sha512CompressChip {
    /// Constrains that memory accesses are correct.
    fn eval_memory<AB: MemoryAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Sha512CompressCols<AB::Var>,
    ) {
        // Assert `i` was read and written to correctly.
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk,
            local.h_ptr + AB::F::from_canonical_u32(8 * 8),
            &local.i_mem,
            local.is_real,
        );
        let reduced_prev_i = local.i_mem.prev_value().reduce::<AB>();
        builder
            .when(local.is_real)
            .assert_eq(reduced_prev_i, local.i);
        let reduced_next_i = local.i_mem.value().reduce::<AB>();
        builder
            .when(local.is_real)
            .assert_eq(reduced_next_i, local.i + AB::Expr::one());
        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::F::one(),
            local.i,
            AB::F::from_canonical_usize(80),
            local.shard,
            local.channel,
            local.is_real,
        );

        for j in 0..2 {
            // Assert `w_i` was read correctly.
            builder.eval_memory_access(
                local.shard,
                local.channel,
                local.clk,
                local.w_ptr
                    + local.i * AB::F::from_canonical_u32(8)
                    + AB::F::from_canonical_u32(j as u32 * 4),
                &local.w_i[j],
                local.is_real,
            );
            // Assert `k_i` was read correctly.
            builder.eval_memory_access(
                local.shard,
                local.channel,
                local.clk,
                local.h_ptr
                    + AB::F::from_canonical_u32(9 * 8)
                    + local.i * AB::F::from_canonical_u32(8)
                    + AB::F::from_canonical_u32(j as u32 * 4),
                &local.k_i[j],
                local.is_real,
            );
            // Assert `h` was read correctly - the result is checked at the end.
            for m in 0..8 {
                builder.eval_memory_access(
                    local.shard,
                    local.channel,
                    local.clk,
                    local.h_ptr + AB::F::from_canonical_u32(m as u32 * 8 + j as u32 * 4),
                    &local.h[m * 2 + j],
                    local.is_real,
                );
            }
        }
    }

    fn eval_compression_ops<AB: WordAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Sha512CompressCols<AB::Var>,
    ) {
        let k_i_lo = local.k_i[0].value();
        let k_i_hi = local.k_i[1].value();
        let k_i: Word64<AB::Var> = k_i_lo.into_iter().chain(*k_i_hi).collect();

        let w_i_lo = local.w_i[0].value();
        let w_i_hi = local.w_i[1].value();
        let w_i: Word64<AB::Var> = w_i_lo.into_iter().chain(*w_i_hi).collect();

        // Assemble the loaded state into `Word64`s.
        fn helper<T: Clone>(local: &Sha512CompressCols<T>, i: usize) -> Word64<T> {
            local.h[i * 2]
                .prev_value()
                .clone()
                .into_iter()
                .chain(local.h[i * 2 + 1].prev_value().clone())
                .collect()
        }
        let a = helper(local, 0);
        let b = helper(local, 1);
        let c = helper(local, 2);
        let d = helper(local, 3);
        let e = helper(local, 4);
        let f = helper(local, 5);
        let g = helper(local, 6);
        let h = helper(local, 7);

        // S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
        // Calculate e rightrotate 14.
        FixedRotateRight64Operation::<AB::F>::eval(
            builder,
            e,
            14,
            local.e_rr_14,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // Calculate e rightrotate 18.
        FixedRotateRight64Operation::<AB::F>::eval(
            builder,
            e,
            18,
            local.e_rr_18,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // Calculate e rightrotate 41.
        FixedRotateRight64Operation::<AB::F>::eval(
            builder,
            e,
            41,
            local.e_rr_41,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // Calculate (e rightrotate 14) xor (e rightrotate 18).
        Xor64Operation::<AB::F>::eval(
            builder,
            local.e_rr_14.value,
            local.e_rr_18.value,
            local.s1_intermediate,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // Calculate S1 := ((e rightrotate 14) xor (e rightrotate 18)) xor (e rightrotate 41).
        Xor64Operation::<AB::F>::eval(
            builder,
            local.s1_intermediate.value,
            local.e_rr_41.value,
            local.s1,
            local.shard,
            &local.channel,
            local.is_real,
        );

        // Calculate ch := (e and f) xor ((not e) and g).
        // Calculate e and f.
        And64Operation::<AB::F>::eval(
            builder,
            e,
            f,
            local.e_and_f,
            local.shard,
            local.channel,
            local.is_real,
        );
        // Calculate not e.
        Not64Operation::<AB::F>::eval(
            builder,
            e,
            local.e_not,
            local.shard,
            local.channel,
            local.is_real,
        );
        // Calculate (not e) and g.
        And64Operation::<AB::F>::eval(
            builder,
            local.e_not.value,
            g,
            local.e_not_and_g,
            local.shard,
            local.channel,
            local.is_real,
        );
        // Calculate ch := (e and f) xor ((not e) and g).
        Xor64Operation::<AB::F>::eval(
            builder,
            local.e_and_f.value,
            local.e_not_and_g.value,
            local.ch,
            local.shard,
            &local.channel,
            local.is_real,
        );

        // Calculate temp1 := h + S1 + ch + k[i] + w[i].
        Add64Operation::<AB::F>::eval(
            builder,
            h,
            local.s1.value,
            local.temp1[0],
            local.shard,
            local.channel,
            local.is_real.into(),
        );
        Add64Operation::<AB::F>::eval(
            builder,
            local.temp1[0].value,
            local.ch.value,
            local.temp1[1],
            local.shard,
            local.channel,
            local.is_real.into(),
        );
        Add64Operation::<AB::F>::eval(
            builder,
            local.temp1[1].value,
            k_i,
            local.temp1[2],
            local.shard,
            local.channel,
            local.is_real.into(),
        );
        Add64Operation::<AB::F>::eval(
            builder,
            local.temp1[2].value,
            w_i,
            local.temp1[3],
            local.shard,
            local.channel,
            local.is_real.into(),
        );

        // Calculate S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39).
        // Calculate a rightrotate 28.
        FixedRotateRight64Operation::<AB::F>::eval(
            builder,
            a,
            28,
            local.a_rr_28,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // Calculate a rightrotate 34.
        FixedRotateRight64Operation::<AB::F>::eval(
            builder,
            a,
            34,
            local.a_rr_34,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // Calculate a rightrotate 22.
        FixedRotateRight64Operation::<AB::F>::eval(
            builder,
            a,
            39,
            local.a_rr_39,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // Calculate (a rightrotate 28) xor (a rightrotate 34).
        Xor64Operation::<AB::F>::eval(
            builder,
            local.a_rr_28.value,
            local.a_rr_34.value,
            local.s0_intermediate,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // Calculate S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39).
        Xor64Operation::<AB::F>::eval(
            builder,
            local.s0_intermediate.value,
            local.a_rr_39.value,
            local.s0,
            local.shard,
            &local.channel,
            local.is_real,
        );

        // Calculate maj := (a and b) xor (a and c) xor (b and c).
        // Calculate a and b.
        And64Operation::<AB::F>::eval(
            builder,
            a,
            b,
            local.a_and_b,
            local.shard,
            local.channel,
            local.is_real,
        );
        // Calculate a and c.
        And64Operation::<AB::F>::eval(
            builder,
            a,
            c,
            local.a_and_c,
            local.shard,
            local.channel,
            local.is_real,
        );
        // Calculate b and c.
        And64Operation::<AB::F>::eval(
            builder,
            b,
            c,
            local.b_and_c,
            local.shard,
            local.channel,
            local.is_real,
        );
        // Calculate (a and b) xor (a and c).
        Xor64Operation::<AB::F>::eval(
            builder,
            local.a_and_b.value,
            local.a_and_c.value,
            local.maj_intermediate,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // Calculate maj := ((a and b) xor (a and c)) xor (b and c).
        Xor64Operation::<AB::F>::eval(
            builder,
            local.maj_intermediate.value,
            local.b_and_c.value,
            local.maj,
            local.shard,
            &local.channel,
            local.is_real,
        );

        // Calculate temp2 := s0 + maj.
        Add64Operation::<AB::F>::eval(
            builder,
            local.s0.value,
            local.maj.value,
            local.temp2,
            local.shard,
            local.channel,
            local.is_real.into(),
        );

        // Calculate d + temp1 for the new value of e.
        Add64Operation::<AB::F>::eval(
            builder,
            d,
            local.temp1[3].value,
            local.d_add_temp1,
            local.shard,
            local.channel,
            local.is_real.into(),
        );

        // Calculate temp1 + temp2 for the new value of a.
        Add64Operation::<AB::F>::eval(
            builder,
            local.temp1[3].value,
            local.temp2.value,
            local.temp1_add_temp2,
            local.shard,
            local.channel,
            local.is_real.into(),
        );

        // Assert the values were correctly updated according to:
        // h := g
        // g := f
        // f := e
        // e := d + temp1
        // d := c
        // c := b
        // b := a
        // a := temp1 + temp2

        fn helper2<T: Clone>(local: &Sha512CompressCols<T>, i: usize) -> Word64<T> {
            local.h[i * 2]
                .value()
                .clone()
                .into_iter()
                .chain(local.h[i * 2 + 1].value().clone())
                .collect()
        }
        let next_a = helper2(local, 0);
        let next_b = helper2(local, 1);
        let next_c = helper2(local, 2);
        let next_d = helper2(local, 3);
        let next_e = helper2(local, 4);
        let next_f = helper2(local, 5);
        let next_g = helper2(local, 6);
        let next_h = helper2(local, 7);

        fn assert_word64_eq<AB: WordAirBuilder>(
            builder: &mut AB,
            is_real: AB::Var,
            left: Word64<AB::Var>,
            right: Word64<AB::Var>,
        ) {
            let l = left.to_le_words();
            let r = right.to_le_words();
            builder.when(is_real).assert_word_eq(l[0], r[0]);
            builder.when(is_real).assert_word_eq(l[1], r[1]);
        }

        assert_word64_eq(builder, local.is_real, next_h, g);
        assert_word64_eq(builder, local.is_real, next_g, f);
        assert_word64_eq(builder, local.is_real, next_f, e);
        assert_word64_eq(builder, local.is_real, next_e, local.d_add_temp1.value);
        assert_word64_eq(builder, local.is_real, next_d, c);
        assert_word64_eq(builder, local.is_real, next_c, b);
        assert_word64_eq(builder, local.is_real, next_b, a);
        assert_word64_eq(builder, local.is_real, next_a, local.temp1_add_temp2.value);
    }
}
