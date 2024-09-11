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
//const R_2: u32 = 12;
//const R_3: u32 = 8;
//const R_4: u32 = 7;

#[derive(Default)]
pub struct Blake2sXorRotateRightChip;

impl Blake2sXorRotateRightChip {
    pub fn new() -> Self {
        Blake2sXorRotateRightChip
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blake2sXorRotateRightEvent {
    pub lookup_id: usize,
    pub clk: u32,
    pub shard: u32,
    pub channel: u32,
    pub a_ptr: u32,
    pub b_ptr: u32,
    pub rot: u32,
    pub a_reads_writes: Vec<MemoryWriteRecord>,
    pub b_reads: Vec<MemoryReadRecord>,
}

impl Syscall for Blake2sXorRotateRightChip {
    fn execute(&self, ctx: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let clk_init = ctx.clk;
        let shard = ctx.current_shard();
        let lookup_id = ctx.syscall_lookup_id;
        let channel = ctx.current_channel();

        let a_ptr = arg1;
        let b_ptr = arg2;

        let a = ctx.slice_unsafe(a_ptr, 4);
        let (b_reads, mut b) = ctx.mr_slice(b_ptr, 5);

        let rot = b[4].clone();
        b.truncate(4);

        let xor = a
            .into_iter()
            .zip(b.into_iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u32>>();

        let rotate_right = xor
            .into_iter()
            .map(|xor_i| xor_i.rotate_right(rot))
            .collect::<Vec<u32>>();

        ctx.clk += 1;

        // Write rotate_right to a_ptr.
        let a_reads_writes = ctx.mw_slice(a_ptr, rotate_right.as_slice());

        ctx.record_mut()
            .blake2s_xor_rotate_right_events
            .push(Blake2sXorRotateRightEvent {
                lookup_id,
                clk: clk_init,
                shard,
                channel,
                a_ptr,
                b_ptr,
                rot,
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
struct Blake2sXorRotateRightCols<T> {
    pub clk: T,
    pub shard: T,
    pub channel: T,
    pub nonce: T,
    pub is_real: T,

    pub a_ptr: T,
    pub b_ptr: T,

    pub a: [MemoryWriteCols<T>; 4],
    pub b: [MemoryReadCols<T>; 5], // includes rotation constant

    pub xor: [XorOperation<T>; 4],
    pub rotate_right: [FixedRotateRightOperation<T>; 4],
}

impl<T: PrimeField32> BaseAir<T> for Blake2sXorRotateRightChip {
    fn width(&self) -> usize {
        size_of::<Blake2sXorRotateRightCols<u8>>()
    }
}

impl<'a> WithEvents<'a> for Blake2sXorRotateRightChip {
    type Events = &'a [Blake2sXorRotateRightEvent];
}

impl<F: PrimeField32> MachineAir<F> for Blake2sXorRotateRightChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Blake2sXorRotateRightChip".to_string()
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        output: &mut Self::Record,
    ) -> RowMajorMatrix<F> {
        let mut rows = vec![];
        let width = <Blake2sXorRotateRightChip as BaseAir<F>>::width(self);
        let mut new_byte_lookup_events = Vec::new();
        for event in input.events() {
            let shard = event.shard;
            let mut row = vec![F::zero(); width];
            let cols: &mut Blake2sXorRotateRightCols<F> = row.as_mut_slice().borrow_mut();

            cols.clk = F::from_canonical_u32(event.clk);
            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u32(event.channel);
            cols.a_ptr = F::from_canonical_u32(event.a_ptr);
            cols.b_ptr = F::from_canonical_u32(event.b_ptr);

            cols.b[4].populate(event.channel, event.b_reads[4], &mut new_byte_lookup_events); // handle rotation_constant

            let rot = event.b_reads[4].value;

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
                    cols.rotate_right[i].populate(output, shard, event.channel, xor, rot as usize);
                assert_eq!(xor.rotate_right(rot), rotate_right);
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
            let cols: &mut Blake2sXorRotateRightCols<F> =
                trace.values[i * width..(i + 1) * width].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.blake2s_xor_rotate_right_events.is_empty()
    }
}

impl<AB: SphinxAirBuilder> Air<AB> for Blake2sXorRotateRightChip
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &Blake2sXorRotateRightCols<AB::Var> = (*local).borrow();
        let next: &Blake2sXorRotateRightCols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // Eval rotation_constant (included as 4th word in b_ptr).
        let i = 4usize;
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk,
            local.b_ptr + AB::F::from_canonical_u32((i as u32) * 4),
            &local.b[i],
            local.is_real,
        );

        // TODO: get rotation constant from memory somehow
        let _rot = *local.b[4].value();

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
                R_1 as usize, // TODO use value from memory instead !
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
            AB::F::from_canonical_u32(SyscallCode::BLAKE_2S_XOR_ROTATE_RIGHT.syscall_id()),
            local.a_ptr,
            local.b_ptr,
            local.is_real,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::{Instruction, Opcode, SyscallCode};
    use crate::syscall::precompiles::blake2s::R_1;
    use crate::utils::{run_test_with_memory_inspection, setup_logger};
    use crate::Program;

    fn risc_v_program(a_ptr: u32, b_ptr: u32, a: [u32; 4], b: [u32; 5]) -> Program {
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
            SyscallCode::BLAKE_2S_XOR_ROTATE_RIGHT as u32,
            false,
            true,
        ));
        instructions.push(Instruction::new(Opcode::ADD, 10, 0, a_ptr, false, true));
        instructions.push(Instruction::new(Opcode::ADD, 11, 0, b_ptr, false, true));
        instructions.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false));
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn test_blake2s_xor_rotate_right_precompile() {
        setup_logger();

        let a_ptr = 100100100;
        let b_ptr = 200200200;
        let program = risc_v_program(
            a_ptr,
            b_ptr,
            [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, R_1],
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

    fn xor_u32x4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
    }

    fn shuffle_left_1_u32x4(a: [u32; 4]) -> [u32; 4] {
        [a[1], a[2], a[3], a[0]]
    }

    fn shuffle_left_2_u32x4(a: [u32; 4]) -> [u32; 4] {
        [a[2], a[3], a[0], a[1]]
    }

    fn shuffle_left_3_u32x4(a: [u32; 4]) -> [u32; 4] {
        [a[3], a[0], a[1], a[2]]
    }

    fn shuffle_right_1_u32x4(a: [u32; 4]) -> [u32; 4] {
        shuffle_left_3_u32x4(a)
    }
    fn shuffle_right_2_u32x4(a: [u32; 4]) -> [u32; 4] {
        shuffle_left_2_u32x4(a)
    }
    fn shuffle_right_3_u32x4(a: [u32; 4]) -> [u32; 4] {
        shuffle_left_1_u32x4(a)
    }

    fn wrapping_add_u32x4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        [
            a[0].wrapping_add(b[0]),
            a[1].wrapping_add(b[1]),
            a[2].wrapping_add(b[2]),
            a[3].wrapping_add(b[3]),
        ]
    }

    fn rotate_right_const(a: [u32; 4], n: u32) -> [u32; 4] {
        [
            a[0].rotate_right(n),
            a[1].rotate_right(n),
            a[2].rotate_right(n),
            a[3].rotate_right(n),
        ]
    }

    fn quarter_round(v: &mut Vec<[u32; 4]>, rd: u32, rb: u32, m: [u32; 4]) {
        v[0] = wrapping_add_u32x4(wrapping_add_u32x4(v[0], v[1]), m); // m.from_le (?)
        v[3] = rotate_right_const(xor_u32x4(v[3], v[0]), rd);
        v[2] = wrapping_add_u32x4(v[2], v[3]);
        v[1] = rotate_right_const(xor_u32x4(v[1], v[2]), rb);
    }

    fn shuffle(v: &mut Vec<[u32; 4]>) {
        v[1] = shuffle_left_1_u32x4(v[1]);
        v[2] = shuffle_left_2_u32x4(v[2]);
        v[3] = shuffle_left_3_u32x4(v[3]);
    }

    fn unshuffle(v: &mut Vec<[u32; 4]>) {
        v[1] = shuffle_right_1_u32x4(v[1]);
        v[2] = shuffle_right_2_u32x4(v[2]);
        v[3] = shuffle_right_3_u32x4(v[3]);
    }

    fn gather(m: [u32; 16], i0: usize, i1: usize, i2: usize, i3: usize) -> [u32; 4] {
        [m[i0], m[i1], m[i2], m[i3]]
    }

    fn round(v: &mut Vec<[u32; 4]>, m: [u32; 16], s: [usize; 16]) {
        let r1 = 16;
        let r2 = 12;
        let r3 = 8;
        let r4 = 7;

        quarter_round(v, r1, r2, gather(m, s[0], s[2], s[4], s[6]));
        quarter_round(v, r3, r4, gather(m, s[1], s[3], s[5], s[7]));
        shuffle(v);
        quarter_round(v, r1, r2, gather(m, s[8], s[10], s[12], s[14]));
        quarter_round(v, r3, r4, gather(m, s[9], s[11], s[13], s[15]));
        unshuffle(v);
    }

    #[test]
    fn test_blake2s_round_function() {
        fn test_inner(
            input: &mut Vec<[u32; 4]>,
            m: [u32; 16],
            s: [usize; 16],
            output: Vec<[u32; 4]>,
        ) {
            round(input, m, s);
            assert_eq!(input.clone(), output);
        }

        let mut v: Vec<[u32; 4]> = vec![
            [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0xe07c2654, 0x5be0cd19],
        ];

        let m: [u32; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let s: [usize; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        test_inner(
            &mut v,
            m,
            s,
            vec![
                [0x82a01b5d, 0x248bd8f5, 0x1da4b59a, 0xb37b2bd3],
                [0x515f5af4, 0x0301095b, 0xb151a3c2, 0x5e17f96f],
                [0xc561666d, 0x0f291605, 0x990c6d13, 0x76fff6f1],
                [0x1e53bf19, 0x6fe4a680, 0x08e33663, 0x97fd885e],
            ],
        );

        let mut v: Vec<[u32; 4]> = vec![
            [0x01, 0x01, 0x01, 0x01],
            [0x01, 0x01, 0x01, 0x01],
            [0x01, 0x01, 0x01, 0x01],
            [0x01, 0x01, 0x01, 0x01],
        ];

        let m: [u32; 16] = [
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01,
        ];
        let s: [usize; 16] = [
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01,
        ];

        test_inner(
            &mut v,
            m,
            s,
            vec![
                [0x071e8a60, 0x071e8a60, 0x071e8a60, 0x071e8a60],
                [0x072df44c, 0x072df44c, 0x072df44c, 0x072df44c],
                [0x522ca035, 0x522ca035, 0x522ca035, 0x522ca035],
                [0x280137ec, 0x280137ec, 0x280137ec, 0x280137ec],
            ],
        );
    }

    #[test]
    fn test_blake2s_unshuffle_function() {
        let mut v: Vec<[u32; 4]> = vec![
            [0x82a01b5d, 0x248bd8f5, 0x1da4b59a, 0xb37b2bd3],
            [0x0301095b, 0xb151a3c2, 0x5e17f96f, 0x515f5af4],
            [0x990c6d13, 0x76fff6f1, 0xc561666d, 0x0f291605],
            [0x97fd885e, 0x1e53bf19, 0x6fe4a680, 0x08e33663],
        ];

        unshuffle(&mut v);

        assert_eq!(
            v[0].to_vec(),
            vec![0x82a01b5d, 0x248bd8f5, 0x1da4b59a, 0xb37b2bd3]
        );
        assert_eq!(
            v[1].to_vec(),
            vec![0x515f5af4, 0x0301095b, 0xb151a3c2, 0x5e17f96f]
        );
        assert_eq!(
            v[2].to_vec(),
            vec![0xc561666d, 0x0f291605, 0x990c6d13, 0x76fff6f1]
        );
        assert_eq!(
            v[3].to_vec(),
            vec![0x1e53bf19, 0x6fe4a680, 0x08e33663, 0x97fd885e]
        );
    }

    #[test]
    fn test_blake2s_shuffle_function() {
        let mut v: Vec<[u32; 4]> = vec![
            [0xdc0f959e, 0x8c871712, 0xc6a650d4, 0xd26fb9fc],
            [0x408705aa, 0x8d07c52d, 0xb9d6aa3a, 0x88609304],
            [0x5c7a89f8, 0xb5f896c7, 0x81e69eeb, 0xe17775ed],
            [0x87b6b678, 0x7af31ada, 0x5a2defeb, 0x2cdd25e3],
        ];

        shuffle(&mut v);

        assert_eq!(
            v[0].to_vec(),
            vec![0xdc0f959e, 0x8c871712, 0xc6a650d4, 0xd26fb9fc]
        );
        assert_eq!(
            v[1].to_vec(),
            vec![0x8d07c52d, 0xb9d6aa3a, 0x88609304, 0x408705aa]
        );
        assert_eq!(
            v[2].to_vec(),
            vec![0x81e69eeb, 0xe17775ed, 0x5c7a89f8, 0xb5f896c7]
        );
        assert_eq!(
            v[3].to_vec(),
            vec![0x2cdd25e3, 0x87b6b678, 0x7af31ada, 0x5a2defeb]
        );
    }

    #[test]
    fn test_blake2s_quarter_round_function() {
        let mut v: Vec<[u32; 4]> = vec![
            [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0xe07c2654, 0x5be0cd19],
        ];
        let m = [0, 0, 0, 0];
        let rd = 16;
        let rb = 12;

        quarter_round(&mut v, rd, rb, m);

        assert_eq!(
            v[0].to_vec(),
            vec![0xbc1738c6, 0x566d1711, 0x5bf2cd1d, 0x130c253]
        );
        assert_eq!(
            v[1].to_vec(),
            vec![0x1ff85cd8, 0x361a0001, 0x6ab383b7, 0xd13ef7a9]
        );
        assert_eq!(
            v[2].to_vec(),
            vec![0xd4c3d380, 0x3b057bed, 0x27b8af00, 0xb49a500a]
        );
        assert_eq!(
            v[3].to_vec(),
            vec![0x6ab9ed19, 0x7f9dcd68, 0xeb49bb8e, 0xf4a5ad0]
        );
    }
}
