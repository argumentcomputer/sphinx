use crate::memory::MemoryCols;
use crate::operations::{Add4Operation, FixedRotateRightOperation, XorOperation};
use crate::runtime::SyscallCode;
use crate::stark::SphinxAirBuilder;
use crate::syscall::precompiles::blake2s::columns::Blake2sRoundCols;
use crate::syscall::precompiles::blake2s::{Blake2sRoundChip, R_1, R_2, R_3, R_4};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::Matrix;
use std::mem::size_of;

impl<T: PrimeField32> BaseAir<T> for Blake2sRoundChip {
    fn width(&self) -> usize {
        size_of::<Blake2sRoundCols<u8>>()
    }
}

impl<AB: SphinxAirBuilder> Air<AB> for Blake2sRoundChip
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &Blake2sRoundCols<AB::Var> = (*local).borrow();
        let next: &Blake2sRoundCols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        for i in 0..16usize {
            // Eval a
            builder.eval_memory_access(
                local.shard,
                local.channel,
                local.clk + AB::F::from_canonical_u32(1), // We eval 'a' pointer access at clk+1 since 'a', 'b' could be the same,
                local.a_ptr + AB::F::from_canonical_u32((i as u32) * 4),
                &local.a[i],
                local.is_real,
            );

            // Eval b
            builder.eval_memory_access(
                local.shard,
                local.channel,
                local.clk,
                local.b_ptr + AB::F::from_canonical_u32((i as u32) * 4),
                &local.b[i],
                local.is_real,
            );
        }

        // Eval extra-zeroes
        for i in 16..24usize {
            builder.eval_memory_access(
                local.shard,
                local.channel,
                local.clk,
                local.b_ptr + AB::F::from_canonical_u32((i as u32) * 4),
                &local.b[i],
                local.is_real,
            );
        }

        let v1_shuffle_lookup = [1, 2, 3, 0];
        let v2_shuffle_lookup = [2, 3, 0, 1];
        let v3_shuffle_lookup = [3, 0, 1, 2];

        for i in 0..4usize {
            // 1x

            // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le());
            Add4Operation::<AB::F>::eval(
                builder,
                *local.a[i].prev_value(),     // v0
                *local.a[i + 4].prev_value(), // v1
                *local.b[i].value(),          // m1
                *local.b[i + 20].value(),     // zero1
                local.shard,
                local.channel,
                local.is_real,
                local.add[i],
            );

            // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
            XorOperation::<AB::F>::eval(
                builder,
                *local.a[i + 12].prev_value(),
                local.add[i].value,
                local.xor[i],
                local.shard,
                &local.channel,
                local.is_real,
            );
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                local.xor[i].value,
                R_1 as usize,
                local.rotate_right[i],
                local.shard,
                &local.channel,
                local.is_real,
            );

            // v[2] = v[2].wrapping_add(v[3]);
            Add4Operation::<AB::F>::eval(
                builder,
                *local.a[i + 8].prev_value(), // v2
                local.rotate_right[i].value,  // v3 from previous operation
                *local.b[i + 16].value(),     // zero1
                *local.b[i + 20].value(),     // zero2
                local.shard,
                local.channel,
                local.is_real,
                local.add[i + 4],
            );

            // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
            XorOperation::<AB::F>::eval(
                builder,
                *local.a[i + 4].prev_value(),
                local.add[i + 4].value,
                local.xor[i + 4],
                local.shard,
                &local.channel,
                local.is_real,
            );
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                local.xor[i + 4].value,
                R_2 as usize,
                local.rotate_right[i + 4],
                local.shard,
                &local.channel,
                local.is_real,
            );

            // 2x

            // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le());
            Add4Operation::<AB::F>::eval(
                builder,
                local.add[i].value,              // v0 after 1x
                local.rotate_right[i + 4].value, // v1 after 1x
                *local.b[i + 4].value(),         // m2
                *local.b[i + 16].value(),        // zero1
                local.shard,
                local.channel,
                local.is_real,
                local.add[i + 8],
            );

            // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
            XorOperation::<AB::F>::eval(
                builder,
                local.rotate_right[i].value, // v3 after 1x
                local.add[i + 8].value,      // v0 after 1x
                local.xor[i + 8],
                local.shard,
                &local.channel,
                local.is_real,
            );
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                local.xor[i + 8].value,
                R_3 as usize,
                local.rotate_right[i + 8],
                local.shard,
                &local.channel,
                local.is_real,
            );

            // v[2] = v[2].wrapping_add(v[3]);
            Add4Operation::<AB::F>::eval(
                builder,
                local.add[i + 4].value,          // v2 after 1x
                local.rotate_right[i + 8].value, // v3 after previous operation
                *local.b[i + 16].value(),        // zero1
                *local.b[i + 20].value(),        // zero2
                local.shard,
                local.channel,
                local.is_real,
                local.add[i + 12],
            );

            // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
            XorOperation::<AB::F>::eval(
                builder,
                local.rotate_right[i + 4].value, // v1 after 1x
                local.add[i + 12].value,         // v2 after previous operation
                local.xor[i + 12],
                local.shard,
                &local.channel,
                local.is_real,
            );
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                local.xor[i + 12].value,
                R_4 as usize,
                local.rotate_right[i + 12],
                local.shard,
                &local.channel,
                local.is_real,
            );
        }

        self.constrain_shuffled_indices(builder, &local.shuffled_indices, local.is_real);

        for i in 0..4usize {
            // 3x

            // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le());
            Add4Operation::<AB::F>::eval(
                builder,
                local.add[i + 8].value, // v0 after 2x
                local.rotate_right[v1_shuffle_lookup[i] + 12].value, // v1 after 2x
                *local.b[i + 8].value(), // m3
                *local.b[i + 16].value(), // zero1
                local.shard,
                local.channel,
                local.is_real,
                local.add[i + 16],
            );

            // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
            XorOperation::<AB::F>::eval(
                builder,
                local.rotate_right[v3_shuffle_lookup[i] + 8].value, // v3 after 2x
                local.add[i + 16].value,                            // v0 after previous operation
                local.xor[i + 16],
                local.shard,
                &local.channel,
                local.is_real,
            );
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                local.xor[i + 16].value,
                R_1 as usize,
                local.rotate_right[i + 16],
                local.shard,
                &local.channel,
                local.is_real,
            );

            // v[2] = v[2].wrapping_add(v[3]);
            Add4Operation::<AB::F>::eval(
                builder,
                local.add[v2_shuffle_lookup[i] + 12].value, // v2 after 2x
                local.rotate_right[i + 16].value,           // v3 after previous operation
                *local.b[i + 16].value(),                   // zero1
                *local.b[i + 20].value(),                   // zero2
                local.shard,
                local.channel,
                local.is_real,
                local.add[i + 20],
            );

            // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
            XorOperation::<AB::F>::eval(
                builder,
                local.rotate_right[v1_shuffle_lookup[i] + 12].value, // v1 after 2x
                local.add[i + 20].value,                             // v2 after previous operation
                local.xor[i + 20],
                local.shard,
                &local.channel,
                local.is_real,
            );
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                local.xor[i + 20].value,
                R_2 as usize,
                local.rotate_right[i + 20],
                local.shard,
                &local.channel,
                local.is_real,
            );

            // 4x
            // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le());
            Add4Operation::<AB::F>::eval(
                builder,
                local.add[i + 16].value,          // v0 after 3x
                local.rotate_right[i + 20].value, // v1 after 3x
                *local.b[i + 12].value(),         // m4
                *local.b[i + 16].value(),         // zero1
                local.shard,
                local.channel,
                local.is_real,
                local.add[i + 24],
            );

            // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
            XorOperation::<AB::F>::eval(
                builder,
                local.rotate_right[i + 16].value, // v3 after 3x
                local.add[i + 24].value,          // v0 after previous operation
                local.xor[i + 24],
                local.shard,
                &local.channel,
                local.is_real,
            );
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                local.xor[i + 24].value,
                R_3 as usize,
                local.rotate_right[i + 24],
                local.shard,
                &local.channel,
                local.is_real,
            );

            // v[2] = v[2].wrapping_add(v[3]);
            Add4Operation::<AB::F>::eval(
                builder,
                local.add[i + 20].value,          // v2 after 3x
                local.rotate_right[i + 24].value, // v3 after previous operation
                *local.b[i + 16].value(),         // zero1
                *local.b[i + 20].value(),         // zero2
                local.shard,
                local.channel,
                local.is_real,
                local.add[i + 28],
            );

            // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
            XorOperation::<AB::F>::eval(
                builder,
                local.rotate_right[i + 20].value, // v1 after 3x
                local.add[i + 28].value,          // v2 after previous operation
                local.xor[i + 28],
                local.shard,
                &local.channel,
                local.is_real,
            );
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                local.xor[i + 28].value,
                R_4 as usize,
                local.rotate_right[i + 28],
                local.shard,
                &local.channel,
                local.is_real,
            );
        }

        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::BLAKE_2S_ROUND.syscall_id()),
            local.a_ptr,
            local.b_ptr,
            local.is_real,
        )
    }
}
