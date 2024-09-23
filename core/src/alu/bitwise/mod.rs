use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::{AbstractField, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator, ParallelSlice};
use sphinx_derive::AlignedBorrow;

use crate::air::{AluAirBuilder, ByteAirBuilder, MachineAir};
use crate::air::{EventLens, WithEvents, Word};
use crate::bytes::event::ByteRecord;
use crate::bytes::{ByteLookupEvent, ByteOpcode};
use crate::runtime::{ExecutionRecord, Opcode, Program};
use crate::utils::pad_to_power_of_two;

use super::AluEvent;

/// The number of main trace columns for `BitwiseChip`.
pub const NUM_BITWISE_COLS: usize = size_of::<BitwiseCols<u8>>();

/// A chip that implements bitwise operations for the opcodes XOR, OR, and AND.
#[derive(Default)]
pub struct BitwiseChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct BitwiseCols<T> {
    /// The shard number, used for byte lookup table.
    pub shard: T,

    /// The channel number, used for byte lookup table.
    pub channel: T,

    /// The nonce of the operation.
    pub nonce: T,

    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// If the opcode is XOR.
    pub is_xor: T,

    // If the opcode is OR.
    pub is_or: T,

    /// If the opcode is AND.
    pub is_and: T,
}

impl<'a> WithEvents<'a> for BitwiseChip {
    type Events = &'a [AluEvent];
}

impl<F: PrimeField> MachineAir<F> for BitwiseChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Bitwise".to_string()
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let rows = input
            .events()
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_BITWISE_COLS];
                let cols: &mut BitwiseCols<F> = row.as_mut_slice().borrow_mut();
                let mut blu = Vec::new();
                self.event_to_row(event, cols, &mut blu);
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BITWISE_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_BITWISE_COLS, F>(&mut trace.values);

        for i in 0..trace.height() {
            let cols: &mut BitwiseCols<F> =
                trace.values[i * NUM_BITWISE_COLS..(i + 1) * NUM_BITWISE_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn generate_dependencies<EL: EventLens<Self>>(&self, input: &EL, output: &mut ExecutionRecord) {
        let chunk_size = std::cmp::max(input.events().len() / num_cpus::get(), 1);

        let blu_batches = input
            .events()
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                for event in events.iter() {
                    let mut row = [F::zero(); NUM_BITWISE_COLS];
                    let cols: &mut BitwiseCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                }
                blu
            })
            .collect::<Vec<_>>();

        output.add_sharded_byte_lookup_events(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.bitwise_events.is_empty()
    }
}

impl BitwiseChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut BitwiseCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        let a = event.a.to_le_bytes();
        let b = event.b.to_le_bytes();
        let c = event.c.to_le_bytes();

        cols.shard = F::from_canonical_u32(event.shard);
        cols.channel = F::from_canonical_u32(event.channel);
        cols.a = Word::from(event.a);
        cols.b = Word::from(event.b);
        cols.c = Word::from(event.c);

        cols.is_xor = F::from_bool(event.opcode == Opcode::XOR);
        cols.is_or = F::from_bool(event.opcode == Opcode::OR);
        cols.is_and = F::from_bool(event.opcode == Opcode::AND);

        for ((b_a, b_b), b_c) in a.into_iter().zip(b).zip(c) {
            let byte_event = ByteLookupEvent {
                shard: event.shard,
                channel: event.channel,
                opcode: ByteOpcode::try_from(event.opcode).unwrap(),
                a1: u32::from(b_a),
                a2: 0,
                b: u32::from(b_b),
                c: u32::from(b_c),
            };
            blu.add_byte_lookup_event(byte_event);
        }
    }
}

impl<F> BaseAir<F> for BitwiseChip {
    fn width(&self) -> usize {
        NUM_BITWISE_COLS
    }
}

impl<AB> Air<AB> for BitwiseChip
where
    AB: ByteAirBuilder + AluAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BitwiseCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &BitwiseCols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // Get the opcode for the operation.
        let opcode = local.is_xor * ByteOpcode::XOR.as_field::<AB::F>()
            + local.is_or * ByteOpcode::OR.as_field::<AB::F>()
            + local.is_and * ByteOpcode::AND.as_field::<AB::F>();

        // Get a multiplicity of `1` only for a true row.
        let mult = local.is_xor + local.is_or + local.is_and;
        for ((a, b), c) in local.a.into_iter().zip(local.b).zip(local.c) {
            builder.send_byte(
                opcode.clone(),
                a,
                b,
                c,
                local.shard,
                local.channel,
                mult.clone(),
            );
        }

        // Get the cpu opcode, which corresponds to the opcode being sent in the CPU table.
        let cpu_opcode = local.is_xor * Opcode::XOR.as_field::<AB::F>()
            + local.is_or * Opcode::OR.as_field::<AB::F>()
            + local.is_and * Opcode::AND.as_field::<AB::F>();

        // Receive the arguments.
        builder.receive_alu(
            cpu_opcode,
            local.a,
            local.b,
            local.c,
            local.shard,
            local.channel,
            local.nonce,
            local.is_xor + local.is_or + local.is_and,
        );

        let is_real = local.is_xor + local.is_or + local.is_and;
        builder.assert_bool(local.is_xor);
        builder.assert_bool(local.is_or);
        builder.assert_bool(local.is_and);
        builder.assert_bool(is_real);
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;

    use super::BitwiseChip;
    use crate::{
        air::MachineAir,
        alu::AluEvent,
        runtime::{ExecutionRecord, Opcode},
        stark::StarkGenericConfig,
        utils::{uni_stark_prove as prove, uni_stark_verify as verify, BabyBearPoseidon2},
    };

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.bitwise_events = vec![AluEvent::new(0, 0, 0, Opcode::XOR, 25, 10, 19)];
        let chip = BitwiseChip;
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        shard.bitwise_events = [
            AluEvent::new(0, 0, 0, Opcode::XOR, 25, 10, 19),
            AluEvent::new(0, 1, 0, Opcode::OR, 27, 10, 19),
            AluEvent::new(0, 0, 0, Opcode::AND, 2, 10, 19),
        ]
        .repeat(1000);
        let chip = BitwiseChip;
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
