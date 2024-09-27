use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;

use super::{Sha512ExtendChip, Sha512ExtendCols, NUM_SHA512_EXTEND_COLS};
use crate::{
    air::{AluAirBuilder, MemoryAirBuilder, Word64, WordAirBuilder},
    bytes::ByteOpcode,
    memory::MemoryCols,
    operations::{
        Add64Operation, FixedRotateRight64Operation, FixedShiftRight64Operation, Xor64Operation,
    },
    runtime::SyscallCode,
};

impl<F> BaseAir<F> for Sha512ExtendChip {
    fn width(&self) -> usize {
        NUM_SHA512_EXTEND_COLS
    }
}

impl<AB> Air<AB> for Sha512ExtendChip
where
    AB: MemoryAirBuilder + AluAirBuilder + WordAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Initialize columns.
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &Sha512ExtendCols<AB::Var> = (*local).borrow();
        let next: &Sha512ExtendCols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        let nb_bytes_in_word64 = AB::F::from_canonical_u32(8);

        // Check that `15 < i < 80`
        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::F::one(),
            AB::F::from_canonical_usize(15),
            local.i,
            local.shard,
            local.channel,
            local.is_real,
        );
        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::F::one(),
            local.i,
            AB::F::from_canonical_usize(80),
            local.shard,
            local.channel,
            local.is_real,
        );

        // Read w[i-15].
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk,
            local.w_ptr + (local.i - AB::F::from_canonical_u32(15)) * nb_bytes_in_word64,
            &local.w_i_minus_15[0],
            local.is_real,
        );
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk,
            local.w_ptr
                + (local.i - AB::F::from_canonical_u32(15)) * nb_bytes_in_word64
                + AB::F::from_canonical_u32(4),
            &local.w_i_minus_15[1],
            local.is_real,
        );
        let w_i_minus_15_lo = local.w_i_minus_15[0].value();
        let w_i_minus_15_hi = local.w_i_minus_15[1].value();
        let w_i_minus_15: Word64<AB::Var> = w_i_minus_15_lo
            .into_iter()
            .chain(*w_i_minus_15_hi)
            .collect();

        // Read w[i-2].
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk,
            local.w_ptr + (local.i - AB::F::from_canonical_u32(2)) * nb_bytes_in_word64,
            &local.w_i_minus_2[0],
            local.is_real,
        );
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk,
            local.w_ptr
                + (local.i - AB::F::from_canonical_u32(2)) * nb_bytes_in_word64
                + AB::F::from_canonical_u32(4),
            &local.w_i_minus_2[1],
            local.is_real,
        );
        let w_i_minus_2_lo = local.w_i_minus_2[0].value();
        let w_i_minus_2_hi = local.w_i_minus_2[1].value();
        let w_i_minus_2: Word64<AB::Var> =
            w_i_minus_2_lo.into_iter().chain(*w_i_minus_2_hi).collect();

        // Read w[i-16].
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk,
            local.w_ptr + (local.i - AB::F::from_canonical_u32(16)) * nb_bytes_in_word64,
            &local.w_i_minus_16[0],
            local.is_real,
        );
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk,
            local.w_ptr
                + (local.i - AB::F::from_canonical_u32(16)) * nb_bytes_in_word64
                + AB::F::from_canonical_u32(4),
            &local.w_i_minus_16[1],
            local.is_real,
        );
        let w_i_minus_16_lo = local.w_i_minus_16[0].value();
        let w_i_minus_16_hi = local.w_i_minus_16[1].value();
        let w_i_minus_16: Word64<AB::Var> = w_i_minus_16_lo
            .into_iter()
            .chain(*w_i_minus_16_hi)
            .collect();

        // Read w[i-7].
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk,
            local.w_ptr + (local.i - AB::F::from_canonical_u32(7)) * nb_bytes_in_word64,
            &local.w_i_minus_7[0],
            local.is_real,
        );
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk,
            local.w_ptr
                + (local.i - AB::F::from_canonical_u32(7)) * nb_bytes_in_word64
                + AB::F::from_canonical_u32(4),
            &local.w_i_minus_7[1],
            local.is_real,
        );
        let w_i_minus_7_lo = local.w_i_minus_7[0].value();
        let w_i_minus_7_hi = local.w_i_minus_7[1].value();
        let w_i_minus_7: Word64<AB::Var> =
            w_i_minus_7_lo.into_iter().chain(*w_i_minus_7_hi).collect();

        // Compute `s0`.
        // w[i-15] rightrotate 1.
        FixedRotateRight64Operation::<AB::F>::eval(
            builder,
            w_i_minus_15,
            1,
            local.w_i_minus_15_rr_1,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // w[i-15] rightrotate 8.
        FixedRotateRight64Operation::<AB::F>::eval(
            builder,
            w_i_minus_15,
            8,
            local.w_i_minus_15_rr_8,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // w[i-15] rightshift 7.
        FixedShiftRight64Operation::<AB::F>::eval(
            builder,
            w_i_minus_15,
            7,
            local.w_i_minus_15_rs_7,
            local.shard,
            local.channel,
            local.is_real,
        );
        // (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8)
        Xor64Operation::<AB::F>::eval(
            builder,
            local.w_i_minus_15_rr_1.value,
            local.w_i_minus_15_rr_8.value,
            local.s0_intermediate,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
        Xor64Operation::<AB::F>::eval(
            builder,
            local.s0_intermediate.value,
            local.w_i_minus_15_rs_7.value,
            local.s0,
            local.shard,
            &local.channel,
            local.is_real,
        );

        // Compute `s1`.
        // w[i-2] rightrotate 19.
        FixedRotateRight64Operation::<AB::F>::eval(
            builder,
            w_i_minus_2,
            19,
            local.w_i_minus_2_rr_19,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // w[i-2] rightrotate 61.
        FixedRotateRight64Operation::<AB::F>::eval(
            builder,
            w_i_minus_2,
            61,
            local.w_i_minus_2_rr_61,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // w[i-2] rightshift 6.
        FixedShiftRight64Operation::<AB::F>::eval(
            builder,
            w_i_minus_2,
            6,
            local.w_i_minus_2_rs_6,
            local.shard,
            local.channel,
            local.is_real,
        );
        // (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61)
        Xor64Operation::<AB::F>::eval(
            builder,
            local.w_i_minus_2_rr_19.value,
            local.w_i_minus_2_rr_61.value,
            local.s1_intermediate,
            local.shard,
            &local.channel,
            local.is_real,
        );
        // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
        Xor64Operation::<AB::F>::eval(
            builder,
            local.s1_intermediate.value,
            local.w_i_minus_2_rs_6.value,
            local.s1,
            local.shard,
            &local.channel,
            local.is_real,
        );

        // s2 := w[i-16] + s0 + w[i-7] + s1.
        // let s2_0 = cols.s2[0].populate(output, shard, event.channel, w_i_minus_16, s0);
        // let s2_1 = cols.s2[1].populate(output, shard, event.channel, s2_0, w_i_minus_7);
        // let s2_2 = cols.s2[2].populate(output, shard, event.channel, s2_1, s1);
        Add64Operation::<AB::F>::eval(
            builder,
            w_i_minus_16,
            local.s0.value,
            local.s2[0],
            local.shard,
            local.channel,
            local.is_real.into(),
        );
        Add64Operation::<AB::F>::eval(
            builder,
            local.s2[0].value,
            w_i_minus_7,
            local.s2[1],
            local.shard,
            local.channel,
            local.is_real.into(),
        );
        Add64Operation::<AB::F>::eval(
            builder,
            local.s2[1].value,
            local.s1.value,
            local.s2[2],
            local.shard,
            local.channel,
            local.is_real.into(),
        );

        // Write `s2` to `w[i]`.
        builder.eval_memory_access_slice(
            local.shard,
            local.channel,
            local.clk,
            local.w_ptr + local.i * nb_bytes_in_word64,
            &local.w_i,
            local.is_real,
        );

        let s2 = local.s2[2].value.to_le_words();
        builder.assert_word_eq(*local.w_i[0].value(), s2[0]);
        builder.assert_word_eq(*local.w_i[1].value(), s2[1]);

        // Receive syscall event
        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::SHA512_EXTEND.syscall_id()),
            local.w_ptr,
            local.i,
            local.is_real,
        );

        // Assert that is_real is a bool.
        builder.assert_bool(local.is_real);
    }
}
