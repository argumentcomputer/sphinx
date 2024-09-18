use crate::bytes::event::ByteRecord;
use crate::memory::{MemoryCols, MemoryReadCols, MemoryWriteCols};
use crate::operations::{Add4Operation, FixedRotateRightOperation, XorOperation};
use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};
use crate::stark::SphinxAirBuilder;
use crate::utils::pad_rows;
use crate::{
    air::{EventLens, MachineAir, WithEvents},
    runtime::{ExecutionRecord, Program, Syscall, SyscallCode, SyscallContext},
};
use core::borrow::{Borrow, BorrowMut};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use serde::Deserialize;
use serde::Serialize;
use sphinx_derive::AlignedBorrow;
use std::mem::size_of;

const R_1: u32 = 16;
const R_2: u32 = 12;
const R_3: u32 = 8;
const R_4: u32 = 7;

#[derive(Default)]
pub struct Blake2sQuarterRound2xChip;

impl Blake2sQuarterRound2xChip {
    pub fn new() -> Self {
        Blake2sQuarterRound2xChip
    }
    pub fn constrain_shuffled_indices<AB: SphinxAirBuilder>(
        &self,
        builder: &mut AB,
        shuffled_indices: &[AB::Var],
        is_real: AB::Var,
    ) {
        for index in 0..4 {
            builder
                .when(is_real)
                .assert_eq(shuffled_indices[index], AB::F::from_canonical_usize(0));
        }
        for index in 4..shuffled_indices.len() {
            builder
                .when(is_real)
                .assert_eq(shuffled_indices[index], AB::F::from_canonical_usize(1));
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blake2sQuarterRound2xEvent {
    pub lookup_id: usize,
    pub clk: u32,
    pub shard: u32,
    pub channel: u32,
    pub a_ptr: u32,
    pub b_ptr: u32,

    pub a_reads_writes: Vec<MemoryWriteRecord>,
    pub b_reads: Vec<MemoryReadRecord>,
}

impl Syscall for Blake2sQuarterRound2xChip {
    fn execute(&self, ctx: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let clk_init = ctx.clk;
        let shard = ctx.current_shard();
        let lookup_id = ctx.syscall_lookup_id;
        let channel = ctx.current_channel();

        let a_ptr = arg1;
        let b_ptr = arg2;

        // a: v[0] || v[1] || v[2] || v[3] || v[4] || v[5] || v[6] || v[7] || v[8] || v[9] || v[10] || v[11] || v[12] || v[13] || v[14] || v[15] ||
        let mut a = ctx.slice_unsafe(a_ptr, 16);
        let mut a_clone = a.clone();

        // b: m1[0] || m1[1] || m1[2] || m1[3] || || m2[0] || m2[1] || m2[2] || m2[3] || 0 || 0 || 0 || 0 || 0 || 0 || 0 || 0 ||
        let (b_reads, b) = ctx.mr_slice(b_ptr, 16);

        // 1x (m1, R1, R2)
        // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le()); (m1)
        for ((v0, v1), m) in a[0..4]
            .iter_mut()
            .zip(a_clone[4..8].iter())
            .zip(b[0..4].iter())
        {
            *v0 = (*v0).wrapping_add(*v1).wrapping_add(*m);
        }
        a_clone = a.clone();

        // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
        for (v3, v0) in a[12..16].iter_mut().zip(a_clone[0..4].iter()) {
            *v3 = (*v3 ^ *v0).rotate_right(R_1);
        }
        a_clone = a.clone();

        // v[2] = v[2].wrapping_add(v[3]);
        for (v2, v3) in a[8..12].iter_mut().zip(a_clone[12..16].iter()) {
            *v2 = (*v2).wrapping_add(*v3);
        }
        a_clone = a.clone();

        // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
        for (v1, v2) in a[4..8].iter_mut().zip(a_clone[8..12].iter()) {
            *v1 = (*v1 ^ *v2).rotate_right(R_2);
        }

        // 2x (m2, R3, R4)
        let mut a = a.clone(); // a after 1x quarter_round
        let mut a_clone = a.clone();

        // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le()); (m2)
        for ((v0, v1), m) in a[0..4]
            .iter_mut()
            .zip(a_clone[4..8].iter())
            .zip(b[4..8].iter())
        {
            *v0 = (*v0).wrapping_add(*v1).wrapping_add(*m);
        }
        a_clone = a.clone();

        // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
        for (v3, v0) in a[12..16].iter_mut().zip(a_clone[0..4].iter()) {
            *v3 = (*v3 ^ *v0).rotate_right(R_3);
        }
        a_clone = a.clone();

        // v[2] = v[2].wrapping_add(v[3]);
        for (v2, v3) in a[8..12].iter_mut().zip(a_clone[12..16].iter()) {
            *v2 = (*v2).wrapping_add(*v3);
        }
        a_clone = a.clone();

        // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
        for (v1, v2) in a[4..8].iter_mut().zip(a_clone[8..12].iter()) {
            *v1 = (*v1 ^ *v2).rotate_right(R_4);
        }

        // shuffle
        // v[1]
        a[4..8].swap(0, 3);
        a[4..8].swap(0, 1);
        a[4..8].swap(1, 2);

        // v[2]
        a[8..12].swap(0, 2);
        a[8..12].swap(1, 3);

        // v[3]
        a[12..16].swap(2, 3);
        a[12..16].swap(1, 2);
        a[12..16].swap(0, 1);

        ctx.clk += 1;
        // Write rotate_right to a_ptr.
        let a_reads_writes = ctx.mw_slice(a_ptr, a.as_slice());

        ctx.record_mut()
            .blake2s_quarter_round_2x_events
            .push(Blake2sQuarterRound2xEvent {
                lookup_id,
                clk: clk_init,
                shard,
                channel,
                a_ptr,
                b_ptr,
                a_reads_writes,
                b_reads,
            });

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
struct Blake2sQuarterRound2xCols<T> {
    pub clk: T,
    pub shard: T,
    pub channel: T,
    pub nonce: T,
    pub is_real: T,

    pub a_ptr: T,
    pub b_ptr: T,

    pub shuffled_indices: [T; 16],

    pub a: [MemoryWriteCols<T>; 16],
    pub b: [MemoryReadCols<T>; 16],

    pub add: [Add4Operation<T>; 8 * 2],
    pub xor: [XorOperation<T>; 8 * 2],
    pub rotate_right: [FixedRotateRightOperation<T>; 8 * 2],
}

impl<T: PrimeField32> BaseAir<T> for Blake2sQuarterRound2xChip {
    fn width(&self) -> usize {
        size_of::<Blake2sQuarterRound2xCols<u8>>()
    }
}

impl<'a> WithEvents<'a> for Blake2sQuarterRound2xChip {
    type Events = &'a [Blake2sQuarterRound2xEvent];
}

impl<F: PrimeField32> MachineAir<F> for Blake2sQuarterRound2xChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Blake2sQuarterRound2xChip".to_string()
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        output: &mut Self::Record,
    ) -> RowMajorMatrix<F> {
        let mut rows = vec![];
        let width = <Blake2sQuarterRound2xChip as BaseAir<F>>::width(self);
        let mut new_byte_lookup_events = Vec::new();
        for event in input.events() {
            let shard = event.shard;
            let mut row = vec![F::zero(); width];
            let cols: &mut Blake2sQuarterRound2xCols<F> = row.as_mut_slice().borrow_mut();

            cols.clk = F::from_canonical_u32(event.clk);
            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u32(event.channel);
            cols.a_ptr = F::from_canonical_u32(event.a_ptr);
            cols.b_ptr = F::from_canonical_u32(event.b_ptr);

            // populate all v, m, 0
            for i in 0..16usize {
                cols.a[i].populate(
                    event.channel,
                    event.a_reads_writes[i],
                    &mut new_byte_lookup_events,
                );
                cols.b[i].populate(event.channel, event.b_reads[i], &mut new_byte_lookup_events);
            }

            let v1_shuffle_lookup = vec![1, 2, 3, 0];
            let v2_shuffle_lookup = vec![2, 3, 0, 1];
            let v3_shuffle_lookup = vec![3, 0, 1, 2];

            // a: v[0] || v[1] || v[2] || v[3] || v[4] || v[5] || v[6] || v[7] || v[8] || v[9] || v[10] || v[11] || v[12] || v[13] || v[14] || v[15] ||
            // b: m1[0] || m1[1] || m1[2] || m1[3] || || m2[0] || m2[1] || m2[2] || m2[3] || 0 || 0 || 0 || 0 || 0 || 0 || 0 || 0 ||
            for i in 0..4usize {
                // 1x (m1, R1, R2)
                let v0 = event.a_reads_writes[i].value;
                let v1 = event.a_reads_writes[i + 4].value;
                let v2 = event.a_reads_writes[i + 8].value;
                let v3 = event.a_reads_writes[i + 12].value;
                let m1 = event.b_reads[i].value;
                let m2 = event.b_reads[i + 4].value;
                let zero1 = event.b_reads[i + 8].value;
                let zero2 = event.b_reads[i + 12].value;
                assert_eq!(zero1, 0);
                assert_eq!(zero2, 0);

                // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le());
                let v0_new = cols.add[i].populate(output, shard, event.channel, v0, v1, m1, zero1);
                assert_eq!(v0 + v1 + m1 + zero1, v0_new);

                // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
                let temp = cols.xor[i].populate(output, shard, event.channel, v3, v0);
                let v3_new =
                    cols.rotate_right[i].populate(output, shard, event.channel, temp, R_1 as usize);
                assert_eq!((v3 ^ v0).rotate_right(R_1), v3_new);

                // v[2] = v[2].wrapping_add(v[3]);
                let v2_new =
                    cols.add[i + 4].populate(output, shard, event.channel, v2, v3, zero1, zero2);
                assert_eq!(v2 + v3 + zero1 + zero2, v2_new);

                // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
                let temp = cols.xor[i + 4].populate(output, shard, event.channel, v1, v2);
                let v1_new = cols.rotate_right[i + 4].populate(
                    output,
                    shard,
                    event.channel,
                    temp,
                    R_2 as usize,
                );
                assert_eq!((v1 ^ v2).rotate_right(R_2), v1_new);

                // 2x (m2, R3, R4)
                let v0 = v0_new;
                let v1 = v1_new;
                let v2 = v2_new;
                let v3 = v3_new;

                // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le()); (m2)
                let v0_new =
                    cols.add[i + 8].populate(output, shard, event.channel, v0, v1, m2, zero1);
                assert_eq!(v0 + v1 + m1 + zero1, v0_new);

                // v[3] = (v[3] ^ v[0]).rotate_right_const(rd); (R3)
                cols.shuffled_indices[i + 12] = F::from_canonical_u32(1);
                let temp = cols.xor[i + 8].populate(output, shard, event.channel, v3, v0);
                let v3_new = cols.rotate_right[v3_shuffle_lookup[i] + 8].populate(
                    output,
                    shard,
                    event.channel,
                    temp,
                    R_3 as usize,
                );
                assert_eq!((v3 ^ v0).rotate_right(R_3), v3_new);

                // v[2] = v[2].wrapping_add(v[3]);
                cols.shuffled_indices[i + 8] = F::from_canonical_u32(1);
                let v2_new = cols.add[v2_shuffle_lookup[i] + 4 + 8].populate(
                    output,
                    shard,
                    event.channel,
                    v2,
                    v3,
                    zero1,
                    zero2,
                );
                assert_eq!(v2 + v3 + zero1 + zero2, v2_new);

                // v[1] = (v[1] ^ v[2]).rotate_right_const(rb); (R4)
                cols.shuffled_indices[i + 4] = F::from_canonical_u32(1);
                let temp = cols.xor[i + 4 + 8].populate(output, shard, event.channel, v1, v2);
                let v1_new = cols.rotate_right[v1_shuffle_lookup[i] + 4 + 8].populate(
                    output,
                    shard,
                    event.channel,
                    temp,
                    R_4 as usize,
                );
                assert_eq!((v1 ^ v2).rotate_right(R_4), v1_new);
            }

            rows.push(row);
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || {
            let row = vec![F::zero(); width];

            row
        });

        let mut trace =
            RowMajorMatrix::<F>::new(rows.into_iter().flatten().collect::<Vec<_>>(), width);

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut Blake2sQuarterRound2xCols<F> =
                trace.values[i * width..(i + 1) * width].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.blake2s_quarter_round_2x_events.is_empty()
    }
}

impl<AB: SphinxAirBuilder> Air<AB> for Blake2sQuarterRound2xChip
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &Blake2sQuarterRound2xCols<AB::Var> = (*local).borrow();
        let next: &Blake2sQuarterRound2xCols<AB::Var> = (*next).borrow();

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

        for i in 0..4usize {
            // 1x

            // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le());
            Add4Operation::<AB::F>::eval(
                builder,
                *local.a[i].value(),     // v0
                *local.a[i + 4].value(), // v1
                *local.b[i].value(),     // m1
                *local.b[i + 8].value(), // zero1
                local.shard,
                local.channel,
                local.is_real,
                local.add[i],
            );

            // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
            // Eval XOR
            XorOperation::<AB::F>::eval(
                builder,
                *local.a[i + 12].value(),
                *local.a[i].value(),
                local.xor[i],
                local.shard,
                &local.channel,
                local.is_real,
            );
            // Eval RotateRight
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
                *local.a[i + 8].value(),  // v2
                *local.a[i + 12].value(), // v3
                *local.b[i + 8].value(),  // zero1
                *local.b[i + 12].value(), // zero2
                local.shard,
                local.channel,
                local.is_real,
                local.add[i + 4],
            );

            // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
            // Eval XOR
            XorOperation::<AB::F>::eval(
                builder,
                *local.a[i + 4].value(),
                *local.a[i + 8].value(),
                local.xor[i + 4],
                local.shard,
                &local.channel,
                local.is_real,
            );

            // Eval RotateRight
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

            let v1_shuffle_lookup = vec![1, 2, 3, 0];
            let v2_shuffle_lookup = vec![2, 3, 0, 1];
            let v3_shuffle_lookup = vec![3, 0, 1, 2];

            // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le());
            Add4Operation::<AB::F>::eval(
                builder,
                local.add[i].value,              // v0 after 1x
                local.rotate_right[i + 4].value, // v1 after 1x
                *local.b[i + 4].value(),         // m2
                *local.b[i + 8].value(),         // zero1
                local.shard,
                local.channel,
                local.is_real,
                local.add[i + 8],
            );

            // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
            // Eval XOR
            XorOperation::<AB::F>::eval(
                builder,
                local.rotate_right[i].value, // v3 after 1x
                local.add[i].value,          // v0 after 1x
                local.xor[i + 8],
                local.shard,
                &local.channel,
                local.is_real,
            );

            // Eval RotateRight
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                local.xor[i + 8].value,
                R_3 as usize,
                local.rotate_right[v3_shuffle_lookup[i] + 8],
                local.shard,
                &local.channel,
                local.is_real,
            );

            // v[2] = v[2].wrapping_add(v[3]);
            Add4Operation::<AB::F>::eval(
                builder,
                local.add[i + 4].value,      // v2 after 1x
                local.rotate_right[i].value, // v3 after 1x
                *local.b[i + 8].value(),     // zero1
                *local.b[i + 12].value(),    // zero2
                local.shard,
                local.channel,
                local.is_real,
                local.add[v2_shuffle_lookup[i] + 12],
            );

            // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
            // Eval XOR
            XorOperation::<AB::F>::eval(
                builder,
                local.rotate_right[i + 4].value, // v1 after 1x
                local.add[i + 4].value,          // v2 after 1x
                local.xor[i + 12],
                local.shard,
                &local.channel,
                local.is_real,
            );

            // Eval RotateRight
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                local.xor[i + 12].value,
                R_4 as usize,
                local.rotate_right[v1_shuffle_lookup[i] + 12],
                local.shard,
                &local.channel,
                local.is_real,
            );
        }

        self.constrain_shuffled_indices(builder, &local.shuffled_indices, local.is_real);

        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::BLAKE_2S_QUARTER_ROUND_2X.syscall_id()),
            local.a_ptr,
            local.b_ptr,
            local.is_real,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::{Instruction, Opcode, SyscallCode};
    use crate::utils::tests::BLAKE2S_QUARTER_ROUND_2X_ELF;
    use crate::utils::{run_test, run_test_with_memory_inspection, setup_logger};
    use crate::Program;

    fn risc_v_program(a_ptr: u32, b_ptr: u32, a: [u32; 16], b: [u32; 16]) -> Program {
        let mut instructions = vec![];
        // memory write a
        for (index, word) in a.into_iter().enumerate() {
            instructions.push(Instruction::new(Opcode::ADD, 29, 0, word, false, true));
            instructions.push(Instruction::new(
                Opcode::ADD,
                30,
                0,
                a_ptr + (index * 4) as u32,
                false,
                true,
            ));
            instructions.push(Instruction::new(Opcode::SW, 29, 30, 0, false, true));
        }

        // memory write b
        for (index, word) in b.into_iter().enumerate() {
            instructions.push(Instruction::new(Opcode::ADD, 29, 0, word, false, true));
            instructions.push(Instruction::new(
                Opcode::ADD,
                30,
                0,
                b_ptr + (index * 4) as u32,
                false,
                true,
            ));
            instructions.push(Instruction::new(Opcode::SW, 29, 30, 0, false, true));
        }

        // Syscall invocation
        instructions.push(Instruction::new(
            Opcode::ADD,
            5,
            0,
            SyscallCode::BLAKE_2S_QUARTER_ROUND_2X as u32,
            false,
            true,
        ));
        instructions.push(Instruction::new(Opcode::ADD, 10, 0, a_ptr, false, true));
        instructions.push(Instruction::new(Opcode::ADD, 11, 0, b_ptr, false, true));
        instructions.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false));
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn test_blake2s_quarter_round_2x_precompile() {
        setup_logger();

        // a: v[0] || v[1] || v[2] || v[3] || v[4] || v[5] || v[6] || v[7] || v[8] || v[9] || v[10] || v[11] || v[12] || v[13] || v[14] || v[15] ||
        // b: m1[0] || m1[1] || m1[2] || m1[3] || || m2[0] || m2[1] || m2[2] || m2[3] || 0 || 0 || 0 || 0 || 0 || 0 || 0 || 0 ||

        let a_ptr = 100100100;
        let b_ptr = 200200200;
        let program = risc_v_program(
            a_ptr,
            b_ptr,
            [
                0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                0xe07c2654, 0x5be0cd19,
            ],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        let (_, memory) = run_test_with_memory_inspection(program);
        let mut result = vec![];
        // result is 4 words, written to a_ptr
        for i in 0..16 {
            result.push(memory.get(&(a_ptr + i * 4)).unwrap().value);
        }

        assert_eq!(
            result,
            [
                0xdc0f959e, 0x8c871712, 0xc6a650d4, 0xd26fb9fc, 0x8d07c52d, 0xb9d6aa3a, 0x88609304,
                0x408705aa, 0x81e69eeb, 0xe17775ed, 0x5c7a89f8, 0xb5f896c7, 0x2cdd25e3, 0x87b6b678,
                0x7af31ada, 0x5a2defeb
            ]
            .to_vec()
        );
    }

    #[test]
    fn test_blake2s_quarter_round_2x_program() {
        setup_logger();
        let program = Program::from(BLAKE2S_QUARTER_ROUND_2X_ELF);
        run_test(program).unwrap();
    }
}
