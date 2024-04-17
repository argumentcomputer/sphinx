use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use std::collections::HashMap;

use wp1_derive::AlignedBorrow;

use crate::air::MachineAir;
use crate::air::SP1AirBuilder;
use crate::cpu::columns::InstructionCols;
use crate::cpu::columns::OpcodeSelectorCols;
use crate::runtime::{ExecutionRecord, Program};
use crate::utils::pad_to_power_of_two;

pub const NUM_PROGRAM_PREPROCESSED_COLS: usize = size_of::<ProgramPreprocessedCols<u8>>();
pub const NUM_PROGRAM_MULT_COLS: usize = size_of::<ProgramMultiplicityCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct ProgramPreprocessedCols<T> {
    pub pc: T,
    pub instruction: InstructionCols<T>,
    pub selectors: OpcodeSelectorCols<T>,
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct ProgramMultiplicityCols<T> {
    pub shard: T,
    pub multiplicity: T,
}

/// A chip that implements addition for the opcodes ADD and ADDI.
#[derive(Default)]
pub struct ProgramChip;

impl ProgramChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> MachineAir<F> for ProgramChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Program".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let rows = program
            .instructions
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, instruction)| {
                let pc = program.pc_base + (i as u32 * 4);
                let mut row = [F::zero(); NUM_PROGRAM_PREPROCESSED_COLS];
                let cols: &mut ProgramPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.pc = F::from_canonical_u32(pc);
                cols.instruction.populate(instruction);
                cols.selectors.populate(instruction);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_PREPROCESSED_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_PROGRAM_PREPROCESSED_COLS, F>(&mut trace.values);

        Some(trace)
    }

    fn generate_dependencies(&self, _input: &ExecutionRecord, _output: &mut ExecutionRecord) {
        // Do nothing since this chip has no dependencies.
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.

        // Collect the number of times each instruction is called from the cpu events.
        // Store it as a map of PC -> count.
        let mut instruction_counts = HashMap::new();
        input.cpu_events.iter().for_each(|event| {
            let pc = event.pc;
            instruction_counts
                .entry(pc)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        });

        let rows = input
            .program
            .instructions
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, _)| {
                let pc = input.program.pc_base + (i as u32 * 4);
                let mut row = [F::zero(); NUM_PROGRAM_MULT_COLS];
                let cols: &mut ProgramMultiplicityCols<F> = row.as_mut_slice().borrow_mut();
                cols.shard = F::from_canonical_u32(input.index);
                cols.multiplicity =
                    F::from_canonical_usize(*instruction_counts.get(&pc).unwrap_or(&0));
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_MULT_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_PROGRAM_MULT_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for ProgramChip {
    fn width(&self) -> usize {
        NUM_PROGRAM_MULT_COLS
    }
}

impl<AB> Air<AB> for ProgramChip
where
    AB: SP1AirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let preprocessed = builder.preprocessed();

        let prep_local = preprocessed.row_slice(0);
        let prep_local: &ProgramPreprocessedCols<AB::Var> = (*prep_local).borrow();
        let mult_local = main.row_slice(0);
        let mult_local: &ProgramMultiplicityCols<AB::Var> = (*mult_local).borrow();

        // Dummy constraint of degree 3.
        builder.assert_eq(
            prep_local.pc * prep_local.pc * prep_local.pc,
            prep_local.pc * prep_local.pc * prep_local.pc,
        );

        // Constrain the interaction with CPU table
        builder.receive_program(
            prep_local.pc,
            prep_local.instruction,
            prep_local.selectors,
            mult_local.shard,
            mult_local.multiplicity,
        );
    }
}

#[cfg(test)]
mod tests {

    use std::{collections::BTreeMap, sync::Arc};

    use p3_baby_bear::BabyBear;

    use p3_matrix::dense::RowMajorMatrix;

    use crate::{
        air::MachineAir,
        program::ProgramChip,
        runtime::{ExecutionRecord, Instruction, Opcode, Program},
    };

    #[test]
    fn generate_trace() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let shard = ExecutionRecord {
            program: Arc::new(Program {
                instructions,
                pc_start: 0,
                pc_base: 0,
                memory_image: BTreeMap::new(),
            }),
            ..Default::default()
        };
        let chip = ProgramChip::new();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
