use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::ParallelSlice;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use sphinx_derive::AlignedBorrow;

use crate::air::Word;
use crate::air::{AluAirBuilder, EventLens, MachineAir, WithEvents};
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::operations::AddOperation;
use crate::runtime::{ExecutionRecord, Opcode, Program};
use crate::utils::pad_to_power_of_two;

use super::AluEvent;

/// The number of main trace columns for `AddSubChip`.
pub const NUM_ADD_SUB_COLS: usize = size_of::<AddSubCols<u8>>();

/// A chip that implements addition for the opcode ADD and SUB.
///
/// SUB is basically an ADD with a re-arrangement of the operands and result.
/// E.g. given the standard ALU op variable name and positioning of `a` = `b` OP `c`,
/// `a` = `b` + `c` should be verified for ADD, and `b` = `a` + `c` (e.g. `a` = `b` - `c`)
/// should be verified for SUB.
#[derive(Default)]
pub struct AddSubChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct AddSubCols<T> {
    /// The shard number, used for byte lookup table.
    pub shard: T,

    /// The channel number, used for byte lookup table.
    pub channel: T,

    /// The nonce of the operation.
    pub nonce: T,

    /// Instance of `AddOperation` to handle addition logic in `AddSubChip`'s ALU operations.
    /// It's result will be `a` for the add operation and `b` for the sub operation.
    pub add_operation: AddOperation<T>,

    /// The first input operand.  This will be `b` for add operations and `c` for sub operations.
    pub operand_1: Word<T>,

    /// The second input operand.  This will be `c` for both operations.
    pub operand_2: Word<T>,

    /// Boolean to indicate whether the row is for an add operation.
    pub is_add: T,

    /// Boolean to indicate whether the row is for a sub operation.
    pub is_sub: T,
}

impl<'a> WithEvents<'a> for AddSubChip {
    type Events = (
        // add events
        &'a [AluEvent],
        // sub events
        &'a [AluEvent],
    );
}

impl<F: PrimeField> MachineAir<F> for AddSubChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "AddSub".to_string()
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        _: &mut Self::Record,
    ) -> RowMajorMatrix<F> {
        let (add_events, sub_events) = input.events();
        // Generate the rows for the trace.
        let chunk_size = std::cmp::max((add_events.len() + sub_events.len()) / num_cpus::get(), 1);
        let merged_events = add_events
            .iter()
            .chain(sub_events.iter())
            .collect::<Vec<_>>();

        let row_batches = merged_events
            .par_chunks(chunk_size)
            .map(|events| {
                let rows = events
                    .iter()
                    .map(|event| {
                        let mut row = [F::zero(); NUM_ADD_SUB_COLS];
                        let cols: &mut AddSubCols<F> = row.as_mut_slice().borrow_mut();
                        let mut blu = Vec::new();
                        self.event_to_row(event, cols, &mut blu);
                        row
                    })
                    .collect::<Vec<_>>();
                rows
            })
            .collect::<Vec<_>>();

        let mut rows: Vec<[F; NUM_ADD_SUB_COLS]> = vec![];
        for row_batch in row_batches {
            rows.extend(row_batch);
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_ADD_SUB_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_ADD_SUB_COLS, F>(&mut trace.values);

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut AddSubCols<F> =
                trace.values[i * NUM_ADD_SUB_COLS..(i + 1) * NUM_ADD_SUB_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn generate_dependencies<EL: EventLens<Self>>(&self, input: &EL, output: &mut Self::Record) {
        let (add_events, sub_events) = input.events();
        let chunk_size = std::cmp::max((add_events.len() + sub_events.len()) / num_cpus::get(), 1);

        let event_iter = add_events
            .chunks(chunk_size)
            .chain(sub_events.chunks(chunk_size));

        let blu_batches = event_iter
            .par_bridge()
            .map(|events| {
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                for event in events.iter() {
                    let mut row = [F::zero(); NUM_ADD_SUB_COLS];
                    let cols: &mut AddSubCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                }
                blu
            })
            .collect::<Vec<_>>();

        output.add_sharded_byte_lookup_events(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.add_events.is_empty() || !shard.sub_events.is_empty()
    }
}

impl AddSubChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut AddSubCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        let is_add = event.opcode == Opcode::ADD;
        cols.shard = F::from_canonical_u32(event.shard);
        cols.channel = F::from_canonical_u32(event.channel);
        cols.is_add = F::from_bool(is_add);
        cols.is_sub = F::from_bool(!is_add);

        let operand_1 = if is_add { event.b } else { event.a };
        let operand_2 = event.c;

        cols.add_operation
            .populate(blu, event.shard, event.channel, operand_1, operand_2);
        cols.operand_1 = Word::from(operand_1);
        cols.operand_2 = Word::from(operand_2);
    }
}

impl<F> BaseAir<F> for AddSubChip {
    fn width(&self) -> usize {
        NUM_ADD_SUB_COLS
    }
}

impl<AB> Air<AB> for AddSubChip
where
    AB: AluAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AddSubCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &AddSubCols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // Evaluate the addition operation.
        AddOperation::<AB::F>::eval(
            builder,
            local.operand_1,
            local.operand_2,
            local.add_operation,
            local.shard,
            local.channel,
            local.is_add + local.is_sub,
        );

        // Receive the arguments.  There are separate receives for ADD and SUB.
        // For add, `add_operation.value` is `a`, `operand_1` is `b`, and `operand_2` is `c`.
        builder.receive_alu(
            Opcode::ADD.as_field::<AB::F>(),
            local.add_operation.value,
            local.operand_1,
            local.operand_2,
            local.shard,
            local.channel,
            local.nonce,
            local.is_add,
        );

        // For sub, `operand_1` is `a`, `add_operation.value` is `b`, and `operand_2` is `c`.
        builder.receive_alu(
            Opcode::SUB.as_field::<AB::F>(),
            local.operand_1,
            local.add_operation.value,
            local.operand_2,
            local.shard,
            local.channel,
            local.nonce,
            local.is_sub,
        );

        let is_real = local.is_add + local.is_sub;
        builder.assert_bool(local.is_add);
        builder.assert_bool(local.is_sub);
        builder.assert_bool(is_real);
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{thread_rng, Rng};

    use super::AddSubChip;
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
        shard.add_events = vec![AluEvent::new(0, 0, 0, Opcode::ADD, 14, 8, 6)];
        let chip = AddSubChip;
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        for i in 0..1000 {
            let operand_1 = thread_rng().gen_range(0..u32::MAX);
            let operand_2 = thread_rng().gen_range(0..u32::MAX);
            let result = operand_1.wrapping_add(operand_2);
            shard.add_events.push(AluEvent::new(
                0,
                i % 2,
                0,
                Opcode::ADD,
                result,
                operand_1,
                operand_2,
            ));
        }
        for i in 0..1000 {
            let operand_1 = thread_rng().gen_range(0..u32::MAX);
            let operand_2 = thread_rng().gen_range(0..u32::MAX);
            let result = operand_1.wrapping_sub(operand_2);
            shard.add_events.push(AluEvent::new(
                0,
                i % 2,
                0,
                Opcode::SUB,
                result,
                operand_1,
                operand_2,
            ));
        }

        let chip = AddSubChip;
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
