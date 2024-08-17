use core::mem::size_of;
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sphinx_core::{
    air::{AirInteraction, EventLens, MachineAir, WithEvents},
    lookup::InteractionKind,
    utils::pad_rows_fixed,
};
use tracing::instrument;

use super::columns::MemoryInitCols;
use crate::{air::Block, memory::MemoryGlobalChip};
use crate::{
    air::RecursionMemoryAirBuilder,
    runtime::{ExecutionRecord, RecursionProgram},
};

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

                    cols.is_real = F::one();

                    row
                })
                .collect::<Vec<_>>(),
        );

        let num_mem_final = last_memory_events.len();
        // Fill in the finalize memory records.
        rows.extend(
            last_memory_events
                .iter()
                .zip(last_memory_events.iter().skip(1).chain([&(
                    F::zero(),
                    F::zero(),
                    Block::from(F::zero()),
                )]))
                .enumerate()
                .map(|(i, ((addr, timestamp, value), (next_addr, _, _)))| {
                    let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                    let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
                    cols.addr = *addr;
                    cols.timestamp = *timestamp;
                    cols.value = *value;
                    cols.is_finalize = F::one();
                    (cols.diff_16bit_limb, cols.diff_12bit_limb) = if i != num_mem_final - 1 {
                        compute_addr_diff(*next_addr, *addr, true)
                    } else {
                        (F::zero(), F::zero())
                    };
                    (cols.addr_16bit_limb, cols.addr_12bit_limb) =
                        compute_addr_diff(*addr, F::zero(), false);

                    cols.is_real = F::one();
                    cols.is_range_check = F::from_bool(i != num_mem_final - 1);

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

/// Computes the difference between the `addr` and `prev_addr` and returns the 16-bit limb and 12-bit
/// limbs of the difference.
///
/// The parameter `subtract_one` is expected to be `true` when `addr` and `prev_addr` are consecutive
/// addresses in the global memory table (we don't allow repeated addresses), and `false` when this
/// function is used to perform the 28-bit range check on the `addr` field.
pub fn compute_addr_diff<F: PrimeField32>(addr: F, prev_addr: F, subtract_one: bool) -> (F, F) {
    let diff = addr.as_canonical_u32() - prev_addr.as_canonical_u32() - u32::from(subtract_one);
    let diff_16bit_limb = diff & 0xffff;
    let diff_12bit_limb = (diff >> 16) & 0xfff;
    (
        F::from_canonical_u32(diff_16bit_limb),
        F::from_canonical_u32(diff_12bit_limb),
    )
}

impl<AB> Air<AB> for MemoryGlobalChip<AB::F>
where
    AB: RecursionMemoryAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &MemoryInitCols<AB::Var> = (*local).borrow();
        let next: &MemoryInitCols<AB::Var> = (*next).borrow();

        // Verify that is_initialize and is_finalize and 1-is_real are bool and that at most one
        // is true.
        builder.assert_bool(local.is_initialize);
        builder.assert_bool(local.is_finalize);
        builder.assert_bool(local.is_real);
        builder.assert_bool(
            local.is_initialize + local.is_finalize + (AB::Expr::one() - local.is_real),
        );
        builder.assert_bool(local.is_range_check);

        // Assert the is_initialize rows come before the is_finalize rows, and those come before the
        // padding rows.
        // The first row should be an initialize row.
        builder.when_first_row().assert_one(local.is_initialize);

        // After an initialize row, we should either have a finalize row, or another initialize row.
        builder
            .when_transition()
            .when(local.is_initialize)
            .assert_one(next.is_initialize + next.is_finalize);

        // After a finalize row, we should either have a finalize row, or a padding row.
        builder
            .when_transition()
            .when(local.is_finalize)
            .assert_one(next.is_finalize + (AB::Expr::one() - next.is_real));

        // After a padding row, we should only have another padding row.
        builder
            .when_transition()
            .when(AB::Expr::one() - local.is_real)
            .assert_zero(next.is_real);

        // The last row should be a padding row or a finalize row.
        builder
            .when_last_row()
            .assert_one(local.is_finalize + AB::Expr::one() - local.is_real);

        // Ensure that the is_range_check column is properly computed.
        // The flag column `is_range_check` is set iff is_finalize is set AND next.is_finalize is set.
        builder
            .when(local.is_range_check)
            .assert_one(local.is_finalize * next.is_finalize);
        builder
            .when_not(local.is_range_check)
            .assert_zero(local.is_finalize * next.is_finalize);

        // Send requests for the 28-bit range checks and ensure that the limbs are correctly
        // computed.
        builder.eval_range_check_28bits(
            next.addr - local.addr - AB::Expr::one(),
            local.diff_16bit_limb,
            local.diff_12bit_limb,
            local.is_range_check,
        );

        builder.eval_range_check_28bits(
            local.addr,
            local.addr_16bit_limb,
            local.addr_12bit_limb,
            local.is_finalize,
        );

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

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use std::marker::PhantomData;
    use std::time::Instant;

    use p3_baby_bear::BabyBear;
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::AbstractField;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use p3_poseidon2::Poseidon2;
    use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
    use sphinx_core::stark::StarkGenericConfig;
    use sphinx_core::{
        air::MachineAir,
        utils::{uni_stark_prove, uni_stark_verify, BabyBearPoseidon2},
    };

    use crate::air::Block;
    use crate::memory::MemoryGlobalChip;
    use crate::runtime::ExecutionRecord;

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::compressed();
        let mut challenger = config.challenger();

        let chip = MemoryGlobalChip {
            fixed_log2_rows: None,
            _phantom: PhantomData,
        };

        let test_vals = (0..16).map(BabyBear::from_canonical_u32).collect_vec();

        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for val in test_vals {
            let event = (val, val, Block::from(BabyBear::zero()));
            input_exec.last_memory_record.push(event);
        }

        // Add a dummy initialize event because the AIR expects at least one.
        input_exec
            .first_memory_record
            .push((BabyBear::zero(), Block::from(BabyBear::zero())));

        println!("input exec: {:?}", input_exec.last_memory_record.len());
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
        println!(
            "trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        let start = Instant::now();
        let proof = uni_stark_prove(&config, &chip, &mut challenger, trace);
        let duration = start.elapsed().as_secs_f64();
        println!("proof duration = {:?}", duration);

        let mut challenger: p3_challenger::DuplexChallenger<
            BabyBear,
            Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
            16,
            8,
        > = config.challenger();
        let start = Instant::now();
        uni_stark_verify(&config, &chip, &mut challenger, &proof)
            .expect("expected proof to be valid");

        let duration = start.elapsed().as_secs_f64();
        println!("verify duration = {:?}", duration);
    }
}
