use crate::stark::SphinxAirBuilder;
use crate::utils::pad_rows;
use crate::{
    air::{EventLens, MachineAir, WithEvents},
    runtime::{ExecutionRecord, Program, Syscall, SyscallCode, SyscallContext},
};
use core::borrow::{Borrow, BorrowMut};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use serde::Deserialize;
use serde::Serialize;
use sphinx_derive::AlignedBorrow;
use std::mem::size_of;

#[derive(Default)]
pub struct EmptyChip;

impl EmptyChip {
    pub fn new() -> Self {
        EmptyChip
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmptyEvent {
    pub lookup_id: usize,
    pub clk: u32,
    pub shard: u32,
    pub channel: u32,
}

impl Syscall for EmptyChip {
    fn execute(&self, ctx: &mut SyscallContext<'_, '_>, _arg1: u32, _arg2: u32) -> Option<u32> {
        let clk = ctx.clk;
        let shard = ctx.current_shard();
        let lookup_id = ctx.syscall_lookup_id;
        let channel = ctx.current_channel();

        ctx.record_mut().empty_events.push(EmptyEvent {
            lookup_id,
            clk,
            shard,
            channel,
        });

        None
    }
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
struct EmptyCols<T> {
    pub clk: T,
    pub shard: T,
    pub channel: T,
    pub nonce: T,
    pub is_real: T,

    pub a: T,
}

impl<T: PrimeField32> BaseAir<T> for EmptyChip {
    fn width(&self) -> usize {
        size_of::<EmptyCols<u8>>()
    }
}

impl<'a> WithEvents<'a> for EmptyChip {
    type Events = &'a [EmptyEvent];
}

impl<F: PrimeField32> MachineAir<F> for EmptyChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "EmptyChip".to_string()
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        _output: &mut Self::Record,
    ) -> RowMajorMatrix<F> {
        let mut rows = vec![];

        let width = <EmptyChip as BaseAir<F>>::width(self);

        for event in input.events() {
            let mut row = vec![F::zero(); width];
            let cols: &mut EmptyCols<F> = row.as_mut_slice().borrow_mut();
            cols.clk = F::from_canonical_u32(event.clk);
            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u32(event.channel);

            cols.a = F::from_canonical_u32(100500u32);

            rows.push(row);
        }

        pad_rows(&mut rows, || {
            let row = vec![F::zero(); width];

            row
        });

        let mut trace =
            RowMajorMatrix::<F>::new(rows.into_iter().flatten().collect::<Vec<_>>(), width);

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut EmptyCols<F> = trace.values[i * width..(i + 1) * width].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.empty_events.is_empty()
    }
}

impl<AB: SphinxAirBuilder> Air<AB> for EmptyChip
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &EmptyCols<AB::Var> = (*local).borrow();
        let next: &EmptyCols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::EMPTY.syscall_id()),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_real,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::{Instruction, Opcode, SyscallCode};
    use crate::utils::{run_test, setup_logger};
    use crate::Program;

    fn risc_v_program() -> Program {
        let mut instructions = vec![];
        instructions.push(Instruction::new(
            Opcode::ADD,
            5,
            0,
            SyscallCode::EMPTY as u32,
            false,
            true,
        ));
        instructions.push(Instruction::new(Opcode::ADD, 10, 0, 0, false, true));
        instructions.push(Instruction::new(Opcode::ADD, 11, 0, 0, false, true));
        instructions.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false));
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn test_empty_precompile() {
        setup_logger();
        let program = risc_v_program();
        run_test(program).unwrap();
    }
}
