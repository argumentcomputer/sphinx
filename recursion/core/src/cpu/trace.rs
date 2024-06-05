use std::borrow::BorrowMut;

use p3_field::{extension::BinomiallyExtendable, Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sphinx_core::{
    air::{BinomialExtension, EventLens, MachineAir, WithEvents},
    utils::pad_rows_fixed,
};
use tracing::instrument;

use crate::{
    air::BinomialExtensionUtils,
    memory::MemoryCols,
    runtime::{ExecutionRecord, Opcode, RecursionProgram, D},
};

use super::{CpuChip, CpuCols, CpuEvent, CPU_COL_MAP, NUM_CPU_COLS};

impl<'a, F: Field> WithEvents<'a> for CpuChip<F> {
    type Events = &'a [CpuEvent<F>];
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> MachineAir<F> for CpuChip<F> 
    where ExecutionRecord<F>: EventLens<CpuChip<F>>
{
    type Record = ExecutionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "CPU".to_string()
    }

    fn generate_dependencies<EL: EventLens<Self>>(&self, _: &EL, _: &mut Self::Record) {
        // There are no dependencies, since we do it all in the runtime. This is just a placeholder.
    }

    #[instrument(name = "generate cpu trace", level = "debug", skip_all, fields(rows = input.events().len()))]
    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = input
            .events()
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_CPU_COLS];
                let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();

                cols.clk = event.clk;
                cols.pc = event.pc;
                cols.fp = event.fp;

                // Populate the instruction related columns.
                cols.selectors.populate(&event.instruction);
                cols.instruction.populate(&event.instruction);

                // Populate the register columns.
                if let Some(record) = &event.a_record {
                    cols.a.populate(record);
                }
                if let Some(record) = &event.b_record {
                    cols.b.populate(record);
                } else {
                    *cols.b.value_mut() = event.instruction.op_b;
                }
                if let Some(record) = &event.c_record {
                    cols.c.populate(record);
                } else {
                    *cols.c.value_mut() = event.instruction.op_c;
                }
                if let Some(record) = &event.memory_record {
                    let memory_cols = cols.opcode_specific.memory_mut();
                    memory_cols.memory.populate(record);
                    memory_cols.memory_addr = record.addr;
                }

                // Populate the branch columns.
                if matches!(
                    event.instruction.opcode,
                    Opcode::BEQ | Opcode::BNE | Opcode::BNEINC
                ) {
                    let branch_cols = cols.opcode_specific.branch_mut();
                    let a_ext: BinomialExtension<F> =
                        BinomialExtensionUtils::from_block(*cols.a.value());
                    let b_ext: BinomialExtension<F> =
                        BinomialExtensionUtils::from_block(*cols.b.value());

                    let (comparison_diff, do_branch) = match event.instruction.opcode {
                        Opcode::BEQ => (a_ext - b_ext, a_ext == b_ext),
                        Opcode::BNE | Opcode::BNEINC => (a_ext - b_ext, a_ext != b_ext),
                        _ => unreachable!(),
                    };

                    branch_cols
                        .comparison_diff
                        .populate((comparison_diff).as_block());
                    branch_cols.comparison_diff_val = comparison_diff;
                    branch_cols.do_branch = F::from_bool(do_branch);
                    branch_cols.next_pc = if do_branch {
                        event.pc + event.instruction.op_c[0]
                    } else {
                        event.pc + F::one()
                    };
                }

                // Populate the public values columns.
                if event.instruction.opcode == Opcode::Commit {
                    let public_values_cols = cols.opcode_specific.public_values_mut();
                    let idx = cols.b.prev_value()[0].as_canonical_u32() as usize;
                    public_values_cols.idx_bitmap[idx] = F::one();
                }

                cols.is_real = F::one();
                row
            })
            .collect::<Vec<_>>();

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = [F::zero(); NUM_CPU_COLS];
                let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                cols.selectors.is_noop = F::one();
                row
            },
            self.fixed_log2_rows,
        );

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        for i in input.events().len()..trace.height() {
            trace.values[i * NUM_CPU_COLS + CPU_COL_MAP.clk] =
                F::from_canonical_u32(4) * F::from_canonical_usize(i);
            trace.values[i * NUM_CPU_COLS + CPU_COL_MAP.instruction.imm_b] =
                F::from_canonical_u32(1);
            trace.values[i * NUM_CPU_COLS + CPU_COL_MAP.instruction.imm_c] =
                F::from_canonical_u32(1);
        }
        trace
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}
