use std::borrow::BorrowMut;

use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use rustc_hash::FxHashMap as HashMap;
use sphinx_core::air::{EventLens, MachineAir, WithEvents};

use super::{
    columns::{RangeCheckMultCols, NUM_RANGE_CHECK_MULT_COLS, NUM_RANGE_CHECK_PREPROCESSED_COLS},
    RangeCheckChip, RangeCheckEvent,
};
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub const NUM_ROWS: usize = 1 << 16;

impl<'a, F: Field> WithEvents<'a> for RangeCheckChip<F> {
    type Events = &'a HashMap<RangeCheckEvent, usize>;
}

impl<F: PrimeField32> MachineAir<F> for RangeCheckChip<F> {
    type Record = ExecutionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "RangeCheck".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_RANGE_CHECK_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let (trace, _) = Self::trace_and_map();

        Some(trace)
    }

    fn generate_dependencies<EL: EventLens<Self>>(&self, _: &EL, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let (_, event_map) = Self::trace_and_map();

        let mut trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_RANGE_CHECK_MULT_COLS * NUM_ROWS],
            NUM_RANGE_CHECK_MULT_COLS,
        );

        for (lookup, mult) in input.events().iter() {
            let (row, index) = event_map[lookup];
            let cols: &mut RangeCheckMultCols<F> = trace.row_mut(row).borrow_mut();

            // Update the trace multiplicity
            cols.multiplicities[index] += F::from_canonical_usize(*mult);
        }

        trace
    }

    fn included(&self, _shard: &Self::Record) -> bool {
        true
    }
}
