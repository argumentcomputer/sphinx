use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
pub use wp1_derive::MachineAir;

use crate::{runtime::Program, stark::MachineRecord};

/// An AIR that is part of a multi table AIR arithmetization.
pub trait MachineAir<F: Field>: BaseAir<F> {
    /// The execution record containing events for producing the air trace.
    type Record: MachineRecord;

    type Program: MachineProgram<F>;

    /// A unique identifier for this AIR as part of a machine.
    fn name(&self) -> String;

    /// Generate the trace for a given execution record.
    ///
    /// - `input` is the execution record containing the events to be written to the trace.
    /// - `output` is the execution record containing events that the `MachineAir` can add to
    ///    the record such as byte lookup requests.
    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F>;

    /// Generate the dependencies for a given execution record.
    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        self.generate_trace(input, output);
    }

    /// Whether this execution record contains events for this air.
    fn included(&self, shard: &Self::Record) -> bool;

    /// The width of the preprocessed trace.
    fn preprocessed_width(&self) -> usize {
        0
    }

    /// Generate the preprocessed trace given a specific program.
    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        None
    }
}

pub trait MachineProgram<F>: Send + Sync {
    fn pc_start(&self) -> F;
}

impl<F: Field> MachineProgram<F> for Program {
    fn pc_start(&self) -> F {
        F::from_canonical_u32(self.pc_start)
    }
}
