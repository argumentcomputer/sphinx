mod alu;
mod branch;
mod jump;
mod memory;
mod operands;

use std::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use wp1_core::air::BaseAirBuilder;

use crate::{
    air::SP1RecursionAirBuilder,
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
};

impl<AB> Air<AB> for CpuChip<AB::F>
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &CpuCols<AB::Var> = (*local).borrow();
        let next: &CpuCols<AB::Var> = (*next).borrow();
        let zero = AB::Expr::zero();
        let one = AB::Expr::one();

        // Constrain the program.
        builder.send_program(local.pc, local.instruction, local.selectors, local.is_real);

        // Constrain the operands.
        self.eval_operands(builder, local);

        // Constrain memory instructions.
        self.eval_memory(builder, local);

        // Constrain ALU instructions.
        self.eval_alu(builder, local);

        // Constrain branches and jumps and constrain the next pc.
        {
            // Expression for the expected next_pc.  This will be added to in `eval_branch` and `eval_jump`
            // to account for possible jumps and branches.
            let mut next_pc = zero;

            self.eval_branch(builder, local, &mut next_pc);

            self.eval_jump(builder, local, next, &mut next_pc);

            // If the instruction is not a jump or branch instruction, then next pc = pc + 1.
            let not_branch_or_jump = one.clone()
                - self.is_branch_instruction::<AB>(local)
                - self.is_jump_instruction::<AB>(local);
            next_pc += not_branch_or_jump.clone() * (local.pc + one);

            builder
                .when_transition()
                .when(next.is_real)
                .assert_eq(next_pc, next.pc);
        }

        // Constrain the syscalls.
        let send_syscall = local.selectors.is_poseidon + local.selectors.is_fri_fold;
        let operands = [
            local.clk.into(),
            local.a.value()[0].into(),
            local.b.value()[0].into(),
            local.c.value()[0] + local.instruction.offset_imm,
        ];
        builder.send_table(local.instruction.opcode, &operands, send_syscall);

        // Constrain the clk.
        self.eval_clk(builder, local, next);
    }
}

impl<F: Field> CpuChip<F> {
    /// Eval the clk.
    ///
    /// For all instructions except for FRI fold, the next clk is the current clk + 4.
    /// For FRI fold, the next clk is the current clk + number of FRI_FOLD iterations.  That value
    /// is stored in the `a` operand.
    pub fn eval_clk<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>, next: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder,
    {
        builder
            .when_transition()
            .when(next.is_real)
            .when_not(local.selectors.is_fri_fold)
            .assert_eq(local.clk.into() + AB::F::from_canonical_u32(4), next.clk);

        builder
            .when_transition()
            .when(next.is_real)
            .when(local.selectors.is_fri_fold)
            .assert_eq(local.clk.into() + local.a.value()[0], next.clk);
    }

    /// Expr to check for alu instructions.
    pub fn is_alu_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_add
            + local.selectors.is_sub
            + local.selectors.is_mul
            + local.selectors.is_div
    }

    /// Expr to check for branch instructions.
    pub fn is_branch_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_beq + local.selectors.is_bne + local.selectors.is_bneinc
    }

    /// Expr to check for jump instructions.
    pub fn is_jump_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_jal + local.selectors.is_jalr
    }

    /// Expr to check for memory instructions.
    pub fn is_memory_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_load + local.selectors.is_store
    }

    /// Expr to check for instructions that only read from operand `a`.
    pub fn is_op_a_read_only_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_beq
            + local.selectors.is_bne
            + local.selectors.is_fri_fold
            + local.selectors.is_poseidon
            + local.selectors.is_store
    }
}
