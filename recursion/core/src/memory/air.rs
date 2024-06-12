use core::mem::size_of;
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use p3_air::{Air, BaseAir};
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sphinx_core::{
    air::{AirInteraction, EventLens, MachineAir, MemoryAirBuilder, WithEvents},
    lookup::InteractionKind,
    utils::pad_rows_fixed,
};
use tracing::instrument;

use super::columns::MemoryInitCols;
use crate::runtime::{ExecutionRecord, RecursionProgram};
use crate::{air::Block, memory::MemoryGlobalChip};

pub(crate) const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();

#[allow(dead_code)]
impl<F: Field> MemoryGlobalChip<F> {
    pub const fn new() -> Self {
        Self {
            fixed_log2_rows: None,
            _phantom: PhantomData,
        }
    }
}

impl<'a, F: Field> WithEvents<'a> for MemoryGlobalChip<F> {
    type Events = (
        // first memory event
        &'a [(F, Block<F>)],
        // last memory event
        &'a [(F, F, Block<F>)],
    );
}

impl<F: PrimeField32> MachineAir<F> for MemoryGlobalChip<F> {
    type Record = ExecutionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "MemoryGlobalChip".to_string()
    }

    fn generate_dependencies<EL: EventLens<Self>>(&self, _: &EL, _: &mut Self::Record) {
        // This is a no-op.
    }

    #[instrument(name = "generate memory trace", level = "debug", skip_all, fields(first_rows = input.events().0.len(), last_rows = input.events().1.len()))]
    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();
        let (first_memory_events, last_memory_events) = input.events();

        // Fill in the initial memory records.
        rows.extend(
            first_memory_events
                .iter()
                .map(|(addr, value)| {
                    let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                    let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
                    cols.addr = *addr;
                    cols.timestamp = F::zero();
                    cols.value = *value;
                    cols.is_initialize = F::one();
                    row
                })
                .collect::<Vec<_>>(),
        );

        // Fill in the finalize memory records.
        rows.extend(
            last_memory_events
                .iter()
                .map(|(addr, timestamp, value)| {
                    let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                    let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
                    cols.addr = *addr;
                    cols.timestamp = *timestamp;
                    cols.value = *value;
                    cols.is_finalize = F::one();
                    row
                })
                .collect::<Vec<_>>(),
        );

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_MEMORY_INIT_COLS],
            self.fixed_log2_rows,
        );

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_INIT_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.first_memory_record.is_empty() || !shard.last_memory_record.is_empty()
    }
}

impl<F: Field> BaseAir<F> for MemoryGlobalChip<F> {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_COLS
    }
}

impl<AB> Air<AB> for MemoryGlobalChip<AB::F>
where
    AB: MemoryAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryInitCols<AB::Var> = (*local).borrow();

        // Verify that is_initialize and is_finalize are bool and that at most one is true.
        builder.assert_bool(local.is_initialize);
        builder.assert_bool(local.is_finalize);
        builder.assert_bool(local.is_initialize + local.is_finalize);

        builder.send(AirInteraction::new(
            vec![
                local.timestamp.into(),
                local.addr.into(),
                local.value[0].into(),
                local.value[1].into(),
                local.value[2].into(),
                local.value[3].into(),
            ],
            local.is_initialize.into(),
            InteractionKind::Memory,
        ));
        builder.receive(AirInteraction::new(
            vec![
                local.timestamp.into(),
                local.addr.into(),
                local.value[0].into(),
                local.value[1].into(),
                local.value[2].into(),
                local.value[3].into(),
            ],
            local.is_finalize.into(),
            InteractionKind::Memory,
        ));
    }
}
