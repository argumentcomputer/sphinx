use std::{borrow::BorrowMut, collections::BTreeMap};

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use super::{
    columns::{ByteMultCols, NUM_BYTE_MULT_COLS, NUM_BYTE_PREPROCESSED_COLS},
    ByteChip, ByteLookupEvent,
};
use crate::{
    air::{EventLens, MachineAir, WithEvents},
    runtime::{ExecutionRecord, Program},
};

pub const NUM_ROWS: usize = 1 << 16;

impl<'a, F: Field> WithEvents<'a> for ByteChip<F> {
    // the byte lookups
    type Events = &'a BTreeMap<u32, BTreeMap<ByteLookupEvent, usize>>;
}

impl<F: Field> MachineAir<F> for ByteChip<F> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Byte".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BYTE_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        // TODO: We should be able to make this a constant. Also, trace / map should be separate.
        // Since we only need the trace and not the map, we can just pass 0 as the shard.
        let (trace, _) = Self::trace_and_map(0);

        Some(trace)
    }

    fn generate_dependencies<EL: EventLens<Self>>(
        &self,
        _input: &EL,
        _output: &mut ExecutionRecord,
    ) {
        // Do nothing since this chip has no dependencies.
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let shard = input.index();
        let (_, event_map) = Self::trace_and_map(shard);

        let mut trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_BYTE_MULT_COLS * NUM_ROWS],
            NUM_BYTE_MULT_COLS,
        );

        for (lookup, mult) in input.events()[&shard].iter() {
            let (row, index) = event_map[lookup];
            let channel = lookup.channel as usize;
            let cols: &mut ByteMultCols<F> = trace.row_mut(row).borrow_mut();

            // Update the trace multiplicity
            cols.mult_channels[channel].multiplicities[index] += F::from_canonical_usize(*mult);

            // Set the shard column as the current shard.
            cols.shard = F::from_canonical_u32(shard);
        }

        trace
    }

    fn included(&self, _shard: &Self::Record) -> bool {
        true
    }
}
