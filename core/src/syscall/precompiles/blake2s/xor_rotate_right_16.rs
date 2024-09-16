use crate::bytes::event::ByteRecord;
use crate::memory::{MemoryCols, MemoryReadCols, MemoryWriteCols};
use crate::operations::{FixedRotateRightOperation, XorOperation};
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

#[derive(Default)]
pub struct Blake2sXorRotateRight16Chip;

impl Blake2sXorRotateRight16Chip {
    pub fn new() -> Self {
        Blake2sXorRotateRight16Chip
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blake2sXorRotateRight16Event {
    pub lookup_id: usize,
    pub clk: u32,
    pub shard: u32,
    pub channel: u32,
    pub a_ptr: u32,
    pub b_ptr: u32,
    pub a_reads_writes: Vec<MemoryWriteRecord>,
    pub b_reads: Vec<MemoryReadRecord>,
}

impl Syscall for Blake2sXorRotateRight16Chip {
    fn execute(&self, ctx: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let clk_init = ctx.clk;
        let shard = ctx.current_shard();
        let lookup_id = ctx.syscall_lookup_id;
        let channel = ctx.current_channel();

        let a_ptr = arg1;
        let b_ptr = arg2;

        let a = ctx.slice_unsafe(a_ptr, 4);
        let (b_reads, b) = ctx.mr_slice(b_ptr, 4);

        let xor = a
            .into_iter()
            .zip(b.into_iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u32>>();

        let rotate_right = xor
            .into_iter()
            .map(|xor_i| xor_i.rotate_right(R_1))
            .collect::<Vec<u32>>();

        ctx.clk += 1;

        // Write rotate_right to a_ptr.
        let a_reads_writes = ctx.mw_slice(a_ptr, rotate_right.as_slice());

        ctx.record_mut()
            .blake2s_xor_rotate_right_16_events
            .push(Blake2sXorRotateRight16Event {
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
struct Blake2sXorRotateRight16Cols<T> {
    pub clk: T,
    pub shard: T,
    pub channel: T,
    pub nonce: T,
    pub is_real: T,

    pub a_ptr: T,
    pub b_ptr: T,

    pub a: [MemoryWriteCols<T>; 4],
    pub b: [MemoryReadCols<T>; 4],

    pub xor: [XorOperation<T>; 4],
    pub rotate_right: [FixedRotateRightOperation<T>; 4],
}

impl<T: PrimeField32> BaseAir<T> for Blake2sXorRotateRight16Chip {
    fn width(&self) -> usize {
        size_of::<Blake2sXorRotateRight16Cols<u8>>()
    }
}

impl<'a> WithEvents<'a> for Blake2sXorRotateRight16Chip {
    type Events = &'a [Blake2sXorRotateRight16Event];
}

impl<F: PrimeField32> MachineAir<F> for Blake2sXorRotateRight16Chip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Blake2sXorRotateRight16Chip".to_string()
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        output: &mut Self::Record,
    ) -> RowMajorMatrix<F> {
        let mut rows = vec![];
        let width = <Blake2sXorRotateRight16Chip as BaseAir<F>>::width(self);
        let mut new_byte_lookup_events = Vec::new();
        for event in input.events() {
            let shard = event.shard;
            let mut row = vec![F::zero(); width];
            let cols: &mut Blake2sXorRotateRight16Cols<F> = row.as_mut_slice().borrow_mut();

            cols.clk = F::from_canonical_u32(event.clk);
            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u32(event.channel);
            cols.a_ptr = F::from_canonical_u32(event.a_ptr);
            cols.b_ptr = F::from_canonical_u32(event.b_ptr);

            for i in 0..4usize {
                cols.a[i].populate(
                    event.channel,
                    event.a_reads_writes[i],
                    &mut new_byte_lookup_events,
                );

                cols.b[i].populate(event.channel, event.b_reads[i], &mut new_byte_lookup_events);

                let a = event.a_reads_writes[i].value;
                let b = event.b_reads[i].value;
                let xor = cols.xor[i].populate(output, shard, event.channel, a, b);
                assert_eq!(a ^ b, xor);

                let rotate_right =
                    cols.rotate_right[i].populate(output, shard, event.channel, xor, R_1 as usize);
                assert_eq!(xor.rotate_right(R_1), rotate_right);
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
            let cols: &mut Blake2sXorRotateRight16Cols<F> =
                trace.values[i * width..(i + 1) * width].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.blake2s_xor_rotate_right_16_events.is_empty()
    }
}

impl<AB: SphinxAirBuilder> Air<AB> for Blake2sXorRotateRight16Chip
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &Blake2sXorRotateRight16Cols<AB::Var> = (*local).borrow();
        let next: &Blake2sXorRotateRight16Cols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        for i in 0..4usize {
            // Eval a
            builder.eval_memory_access(
                local.shard,
                local.channel,
                local.clk + AB::F::from_canonical_u32(1), // We eval 'a' pointer access at clk+1 since 'a', 'b' could be the same,
                local.a_ptr + AB::F::from_canonical_u32((i as u32) * 4),
                &local.a[i],
                local.is_real,
            );

            // Eval b.
            builder.eval_memory_access(
                local.shard,
                local.channel,
                local.clk,
                local.b_ptr + AB::F::from_canonical_u32((i as u32) * 4),
                &local.b[i],
                local.is_real,
            );

            // Eval XOR
            XorOperation::<AB::F>::eval(
                builder,
                *local.a[i].value(),
                *local.b[i].value(),
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
        }

        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::BLAKE_2S_XOR_ROTATE_RIGHT_16.syscall_id()),
            local.a_ptr,
            local.b_ptr,
            local.is_real,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::{Instruction, Opcode, SyscallCode};
    use crate::utils::tests::BLAKE2S_XOR_ROTATE_RIGHT_16_ELF;
    use crate::utils::{run_test, run_test_with_memory_inspection, setup_logger};
    use crate::Program;

    fn risc_v_program(a_ptr: u32, b_ptr: u32, a: [u32; 4], b: [u32; 4]) -> Program {
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
            SyscallCode::BLAKE_2S_XOR_ROTATE_RIGHT_16 as u32,
            false,
            true,
        ));
        instructions.push(Instruction::new(Opcode::ADD, 10, 0, a_ptr, false, true));
        instructions.push(Instruction::new(Opcode::ADD, 11, 0, b_ptr, false, true));
        instructions.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false));
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn test_blake2s_xor_rotate_right_16_precompile() {
        setup_logger();

        let a_ptr = 100100100;
        let b_ptr = 200200200;
        let program = risc_v_program(
            a_ptr,
            b_ptr,
            [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
        );

        let (_, memory) = run_test_with_memory_inspection(program);
        let mut result = vec![];
        // result is 4 words, written to a_ptr
        for i in 0..4 {
            result.push(memory.get(&(a_ptr + i * 4)).unwrap().value);
        }

        assert_eq!(
            result,
            [0xb4383a06, 0xc6092062, 0x2ad923ed, 0x3823feaf].to_vec()
        );
    }

    #[test]
    fn test_blake2s_xor_rotate_right_16_program() {
        setup_logger();
        let program = Program::from(BLAKE2S_XOR_ROTATE_RIGHT_16_ELF);
        run_test(program).unwrap();
    }
}
