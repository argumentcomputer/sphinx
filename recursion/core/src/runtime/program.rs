use backtrace::Backtrace;
use p3_field::Field;
use serde::{Deserialize, Serialize};
use sphinx_core::air::MachineProgram;

use super::Instruction;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionProgram<F> {
    pub instructions: Vec<Instruction<F>>,
    #[serde(skip)]
    pub traces: Vec<Option<Backtrace>>,
}

impl<F: Field> MachineProgram<F> for RecursionProgram<F> {
    fn pc_start(&self) -> F {
        F::zero()
    }
}
