use backtrace::Backtrace;

use super::Instruction;

#[derive(Debug, Clone, Default)]
pub struct RecursionProgram<F> {
    pub instructions: Vec<Instruction<F>>,
    pub traces: Vec<Option<Backtrace>>,
}
