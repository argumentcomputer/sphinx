pub mod branch;
pub mod ecall;
pub mod memory;
pub mod register;

use core::borrow::Borrow;
use p3_air::Air;
use p3_air::AirBuilder as _;
use p3_air::BaseAir;
use p3_field::AbstractField;
use p3_matrix::Matrix;

use crate::air::BaseAirBuilder;
use crate::air::PublicValues;
use crate::air::SP1AirBuilder;
use crate::air::Word;
use crate::air::POSEIDON_NUM_WORDS;
use crate::air::PV_DIGEST_NUM_WORDS;
use crate::bytes::ByteOpcode;
use crate::cpu::columns::OpcodeSelectorCols;
use crate::cpu::columns::{CpuCols, NUM_CPU_COLS};
use crate::cpu::CpuChip;
use crate::runtime::Opcode;

impl<AB> Air<AB> for CpuChip
where
    AB: SP1AirBuilder,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &CpuCols<AB::Var> = (*local).borrow();
        let next: &CpuCols<AB::Var> = (*next).borrow();

        let public_values: PublicValues<_, AB::Expr> =
            builder.public_values().iter().cloned().collect();

        // Program constraints.
        builder.send_program(
            local.pc,
            local.instruction,
            local.selectors,
            local.shard,
            local.is_real,
        );

        // Compute some flags for which type of instruction we are dealing with.
        let is_memory_instruction: AB::Expr = self.is_memory_instruction::<AB>(&local.selectors);
        let is_branch_instruction: AB::Expr = self.is_branch_instruction::<AB>(&local.selectors);
        let is_alu_instruction: AB::Expr = self.is_alu_instruction::<AB>(&local.selectors);

        // Register constraints.
        self.eval_registers::<AB>(builder, local, &is_branch_instruction);

        // Memory instructions.
        self.eval_memory_address_and_access::<AB>(builder, local, &is_memory_instruction);
        self.eval_memory_load::<AB>(builder, local);
        self.eval_memory_store::<AB>(builder, local);

        // ALU instructions.
        builder.send_alu(
            local.instruction.opcode,
            local.op_a_val(),
            local.op_b_val(),
            local.op_c_val(),
            local.shard,
            is_alu_instruction,
        );

        // Branch instructions.
        self.eval_branch_ops::<AB>(builder, is_branch_instruction.clone(), local, next);

        // Jump instructions.
        self.eval_jump_ops::<AB>(builder, local, next);

        // AUIPC instruction.
        self.eval_auipc(builder, local);

        // ECALL instruction.
        self.eval_ecall(builder, local);

        // COMMIT/COMMIT_DEFERRED_PROOFS ecall instruction.
        self.eval_commit(
            builder,
            local,
            &public_values.committed_value_digest,
            &public_values.deferred_proofs_digest,
        );

        // HALT ecall and UNIMPL instruction.
        self.eval_halt_unimpl(builder, local, next);

        // Check that the shard and clk is updated correctly.
        self.eval_shard_clk(builder, local, next);

        // Check that the pc is updated correctly.
        self.eval_pc(builder, local, next, is_branch_instruction.clone());

        // Check public values constraints.
        self.eval_public_values(builder, local, next, &public_values);

        // Check that the is_real flag is correct.
        self.eval_is_real(builder, local, next);
    }
}

impl CpuChip {
    /// Whether the instruction is an ALU instruction.
    pub(crate) fn is_alu_instruction<AB: SP1AirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_alu.into()
    }

    /// Constraints related to jump operations.
    pub(crate) fn eval_jump_ops<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Get the jump specific columns
        let jump_columns = local.opcode_specific_columns.jump();

        let is_jump_instruction = local.selectors.is_jal + local.selectors.is_jalr;

        // Verify that the local.pc + 4 is saved in op_a for both jump instructions.
        // When op_a is set to register X0, the RISC-V spec states that the jump instruction will
        // not have a return destination address (it is effectively a GOTO command).  In this case,
        // we shouldn't verify the return address.
        builder
            .when(is_jump_instruction.clone())
            .when_not(local.instruction.op_a_0)
            .assert_eq(
                local.op_a_val().reduce::<AB>(),
                local.pc + AB::F::from_canonical_u8(4),
            );

        // Verify that the word form of local.pc is correct for JAL instructions.
        builder
            .when(local.selectors.is_jal)
            .assert_eq(jump_columns.pc.reduce::<AB>(), local.pc);

        // Verify that the word form of next.pc is correct for both jump instructions.
        builder
            .when_transition()
            .when(next.is_real)
            .when(is_jump_instruction.clone())
            .assert_eq(jump_columns.next_pc.reduce::<AB>(), next.pc);

        // When the last row is real and it's a jump instruction, assert that local.next_pc <==> jump_column.next_pc
        builder
            .when(local.is_real)
            .when(is_jump_instruction.clone())
            .assert_eq(jump_columns.next_pc.reduce::<AB>(), local.next_pc);

        // Verify that the new pc is calculated correctly for JAL instructions.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            jump_columns.next_pc,
            jump_columns.pc,
            local.op_b_val(),
            local.shard,
            local.selectors.is_jal,
        );

        // Verify that the new pc is calculated correctly for JALR instructions.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            jump_columns.next_pc,
            local.op_b_val(),
            local.op_c_val(),
            local.shard,
            local.selectors.is_jalr,
        );
    }

    /// Constraints related to the AUIPC opcode.
    pub(crate) fn eval_auipc<AB: SP1AirBuilder>(&self, builder: &mut AB, local: &CpuCols<AB::Var>) {
        // Get the auipc specific columns.
        let auipc_columns = local.opcode_specific_columns.auipc();

        // Verify that the word form of local.pc is correct.
        builder
            .when(local.selectors.is_auipc)
            .assert_eq(auipc_columns.pc.reduce::<AB>(), local.pc);

        // Verify that op_a == pc + op_b.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.op_a_val(),
            auipc_columns.pc,
            local.op_b_val(),
            local.shard,
            local.selectors.is_auipc,
        );
    }

    /// Constraints related to the shard and clk.
    ///
    /// This method ensures that all of the shard values are the same and that the clk starts at 0
    /// and is transitioned appropriately.  It will also check that shard values are within 16 bits
    /// and clk values are within 24 bits.  Those range checks are needed for the memory access
    /// timestamp check, which assumes those values are within 2^24.  See [`MemoryAirBuilder::verify_mem_access_ts`].
    pub(crate) fn eval_shard_clk<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Verify that all shard values are the same.
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(local.shard, next.shard);

        // Verify that the shard value is within 16 bits.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            local.shard,
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.shard,
            local.is_real,
        );

        // Verify that the first row has a clk value of 0.
        builder.when_first_row().assert_zero(local.clk);

        // Verify that the clk increments are correct.  Most clk increment should be 4, but for some
        // precompiles, there are additional cycles.
        let num_extra_cycles = self.get_num_extra_ecall_cycles::<AB>(local);

        // We already assert that `local.clk < 2^24`. `num_extra_cycles` is an entry of a word and
        // therefore less than `2^8`, this means that the sum cannot overflow in a 31 bit field.
        let expected_next_clk =
            local.clk + AB::Expr::from_canonical_u32(4) + num_extra_cycles.clone();

        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(expected_next_clk.clone(), next.clk);

        // Range check that the clk is within 24 bits using it's limb values.
        builder.eval_range_check_24bits(
            local.clk,
            local.clk_16bit_limb,
            local.clk_8bit_limb,
            local.shard,
            local.is_real,
        );
    }

    /// Constraints related to the pc for non jump, branch, and halt instructions.
    ///
    /// The function will verify that the pc increments by 4 for all instructions except branch, jump
    /// and halt instructions. Also, it ensures that the pc is carried down to the last row for non-real rows.
    pub(crate) fn eval_pc<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        is_branch_instruction: AB::Expr,
    ) {
        // Verify that if is_sequential_instr is true, assert that local.is_real is true.
        // This is needed for the following constraint, which is already degree 3.
        builder
            .when(local.is_sequential_instr)
            .assert_one(local.is_real);

        // When is_sequential_instr is true, assert that instruction is not branch, jump, or halt.
        // Note that the condition `when(local_is_real)` is implied from the previous constraint.
        let is_halt = self.get_is_halt_syscall::<AB>(builder, local);
        builder.when(local.is_sequential_instr).assert_zero(
            is_branch_instruction + local.selectors.is_jal + local.selectors.is_jalr + is_halt,
        );

        // Verify that the pc increments by 4 for all instructions except branch, jump and halt instructions.
        // The other case is handled by eval_jump, eval_branch and eval_ecall (for halt).
        builder
            .when_transition()
            .when(next.is_real)
            .when(local.is_sequential_instr)
            .assert_eq(local.pc + AB::Expr::from_canonical_u8(4), next.pc);

        // When the last row is real and it's a sequential instruction, assert that local.next_pc <==> local.pc + 4
        builder
            .when(local.is_real)
            .when(local.is_sequential_instr)
            .assert_eq(local.pc + AB::Expr::from_canonical_u8(4), local.next_pc);
    }

    /// Constraints related to the public values.
    pub(crate) fn eval_public_values<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        public_values: &PublicValues<Word<AB::Expr>, AB::Expr>,
    ) {
        // Verify the public value's shard.
        builder
            .when(local.is_real)
            .assert_eq(public_values.shard.clone(), local.shard);

        // Verify the public value's start pc.
        builder
            .when_first_row()
            .assert_eq(public_values.start_pc.clone(), local.pc);

        // Verify the public value's next pc.  We need to handle two cases:
        // 1. The last real row is a transition row.
        // 2. The last real row is the last row.

        // If the last real row is a transition row, verify the public value's next pc.
        builder
            .when_transition()
            .when(local.is_real - next.is_real)
            .assert_eq(public_values.next_pc.clone(), local.next_pc);

        // If the last real row is the last row, verify the public value's next pc.
        builder
            .when_last_row()
            .when(local.is_real)
            .assert_eq(public_values.next_pc.clone(), local.next_pc);
    }

    /// Constraints related to the is_real column.
    ///
    /// This method checks that the is_real column is a boolean.  It also checks that the first row
    /// is 1 and once its 0, it never changes value.
    pub(crate) fn eval_is_real<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Check the is_real flag.  It should be 1 for the first row.  Once its 0, it should never
        // change value.
        builder.assert_bool(local.is_real);
        builder.when_first_row().assert_one(local.is_real);
        builder
            .when_transition()
            .when_not(local.is_real)
            .assert_zero(next.is_real);
    }
}

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}
