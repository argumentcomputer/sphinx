use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;

use super::{Blake2sXorRotate16Chip, Blake2sXorRotate16Cols, NUM_BLAKE2S_XOR_ROTATE_16_COLS};
use crate::{
    air::{AluAirBuilder, BaseAirBuilder, MemoryAirBuilder, WordAirBuilder},
    memory::MemoryCols,
    operations::{FixedRotateRightOperation, XorOperation},
    runtime::SyscallCode,
};

impl<F> BaseAir<F> for Blake2sXorRotate16Chip {
    fn width(&self) -> usize {
        NUM_BLAKE2S_XOR_ROTATE_16_COLS
    }
}

impl<AB> Air<AB> for Blake2sXorRotate16Chip
where
    AB: MemoryAirBuilder + AluAirBuilder + WordAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Initialize columns.
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &Blake2sXorRotate16Cols<AB::Var> = (*local).borrow();
        let next: &Blake2sXorRotate16Cols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        let i_start = AB::F::from_canonical_u32(16);

        // Evaluate the control flags.
        self.eval_flags(builder);

        // Copy over the inputs until the result has been computed (every 48 rows).
        builder
            .when_transition()
            .when_not(local.cycle_16_end.result * local.cycle_48[2])
            .assert_eq(local.shard, next.shard);
        builder
            .when_transition()
            .when_not(local.cycle_16_end.result * local.cycle_48[2])
            .assert_eq(local.clk, next.clk);
        builder
            .when_transition()
            .when_not(local.cycle_16_end.result * local.cycle_48[2])
            .assert_eq(local.channel, next.channel);
        builder
            .when_transition()
            .when_not(local.cycle_16_end.result * local.cycle_48[2])
            .assert_eq(local.w_ptr, next.w_ptr);

        // Read w[0].
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + (local.i - i_start),
            local.w_ptr + AB::F::from_canonical_u32(0),
            &local.w_0,
            local.is_real,
        );

        // Read w[1]
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + (local.i - i_start),
            local.w_ptr + AB::F::from_canonical_u32(4),
            &local.w_1,
            local.is_real,
        );

        // Read w[2]
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + (local.i - i_start),
            local.w_ptr + AB::F::from_canonical_u32(8),
            &local.w_2,
            local.is_real,
        );

        // Read w[3]
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + (local.i - i_start),
            local.w_ptr + AB::F::from_canonical_u32(12),
            &local.w_3,
            local.is_real,
        );

        // Read w[4]
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + (local.i - i_start),
            local.w_ptr + AB::F::from_canonical_u32(16),
            &local.w_4,
            local.is_real,
        );

        // Read w[5]
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + (local.i - i_start),
            local.w_ptr + AB::F::from_canonical_u32(20),
            &local.w_5,
            local.is_real,
        );

        // Read w[6]
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + (local.i - i_start),
            local.w_ptr + AB::F::from_canonical_u32(24),
            &local.w_6,
            local.is_real,
        );

        // Read w[7]
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + (local.i - i_start),
            local.w_ptr + AB::F::from_canonical_u32(28),
            &local.w_7,
            local.is_real,
        );

        XorOperation::<AB::F>::eval(
            builder,
            *local.w_0.value(),
            *local.w_4.value(),
            local.xor_0,
            local.shard,
            &local.channel,
            local.is_real,
        );

        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.xor_0.value,
            16,
            local.rot_0,
            local.shard,
            &local.channel,
            local.is_real,
        );

        XorOperation::<AB::F>::eval(
            builder,
            *local.w_1.value(),
            *local.w_5.value(),
            local.xor_1,
            local.shard,
            &local.channel,
            local.is_real,
        );

        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.xor_1.value,
            16,
            local.rot_1,
            local.shard,
            &local.channel,
            local.is_real,
        );

        XorOperation::<AB::F>::eval(
            builder,
            *local.w_2.value(),
            *local.w_6.value(),
            local.xor_2,
            local.shard,
            &local.channel,
            local.is_real,
        );

        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.xor_2.value,
            16,
            local.rot_2,
            local.shard,
            &local.channel,
            local.is_real,
        );

        XorOperation::<AB::F>::eval(
            builder,
            *local.w_3.value(),
            *local.w_7.value(),
            local.xor_3,
            local.shard,
            &local.channel,
            local.is_real,
        );

        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.xor_3.value,
            16,
            local.rot_3,
            local.shard,
            &local.channel,
            local.is_real,
        );

        // Write w[16]
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + (local.i - i_start),
            local.w_ptr + AB::F::from_canonical_u32(64),
            &local.w_16,
            local.is_real,
        );

        // Write w[17]
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + (local.i - i_start),
            local.w_ptr + AB::F::from_canonical_u32(68),
            &local.w_17,
            local.is_real,
        );

        // Write w[18]
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + (local.i - i_start),
            local.w_ptr + AB::F::from_canonical_u32(72),
            &local.w_18,
            local.is_real,
        );

        // Write w[19]
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + (local.i - i_start),
            local.w_ptr + AB::F::from_canonical_u32(76),
            &local.w_19,
            local.is_real,
        );

        builder.assert_word_eq(*local.w_16.value(), local.rot_0.value);
        builder.assert_word_eq(*local.w_17.value(), local.rot_1.value);
        builder.assert_word_eq(*local.w_18.value(), local.rot_2.value);
        builder.assert_word_eq(*local.w_19.value(), local.rot_3.value);

        // Receive syscall event in first row of 48-cycle.
        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::BLAKE_2S_XOR_ROTATE_16.syscall_id()),
            local.w_ptr,
            AB::Expr::zero(),
            local.cycle_48_start,
        );

        // Assert that is_real is a bool.
        builder.assert_bool(local.is_real);

        // Ensure that all rows in a 48 row cycle has the same `is_real` values.
        builder
            .when_transition()
            .when_not(local.cycle_48_end)
            .assert_eq(local.is_real, next.is_real);

        // Assert that the table ends in nonreal columns. Since each extend ecall is 48 cycles and
        // the table is padded to a power of 2, the last row of the table should always be padding.
        builder.when_last_row().assert_zero(local.is_real);
    }
}
