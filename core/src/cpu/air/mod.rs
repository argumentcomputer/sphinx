pub mod branch;
pub mod memory;

use core::borrow::Borrow;
use itertools::Itertools;
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::AbstractField;

use crate::air::BaseAirBuilder;
use crate::air::PublicValues;
use crate::air::Word;
use crate::air::PV_DIGEST_NUM_WORDS;
use crate::air::{SP1AirBuilder, WordAirBuilder};
use crate::bytes::ByteOpcode;
use crate::cpu::columns::OpcodeSelectorCols;
use crate::cpu::columns::{CpuCols, NUM_CPU_COLS};
use crate::cpu::CpuChip;
use crate::memory::MemoryCols;
use crate::operations::IsZeroOperation;
use crate::runtime::SyscallCode;
use crate::runtime::{MemoryAccessPosition, Opcode};
use p3_matrix::Matrix;

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

        let public_values = PublicValues::<Word<AB::Expr>, AB::Expr>::from_vec(
            &builder
                .public_values()
                .iter()
                .map(|elm| (*elm).into())
                .collect_vec(),
        );

        // Compute some flags for which type of instruction we are dealing with.
        let is_memory_instruction: AB::Expr = self.is_memory_instruction::<AB>(&local.selectors);
        let is_branch_instruction: AB::Expr = self.is_branch_instruction::<AB>(&local.selectors);
        let is_alu_instruction: AB::Expr = self.is_alu_instruction::<AB>(&local.selectors);

        // Program constraints.
        builder.send_program(
            local.pc,
            local.instruction,
            local.selectors,
            local.shard,
            local.is_real,
        );

        // Load immediates into b and c, if the immediate flags are on.
        builder
            .when(local.selectors.imm_b)
            .assert_word_eq(local.op_b_val(), local.instruction.op_b);
        builder
            .when(local.selectors.imm_c)
            .assert_word_eq(local.op_c_val(), local.instruction.op_c);

        // If they are not immediates, read `b` and `c` from memory.
        builder.constraint_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::B as u32),
            local.instruction.op_b[0],
            &local.op_b_access,
            AB::Expr::one() - local.selectors.imm_b,
        );
        builder
            .when_not(local.selectors.imm_b)
            .assert_word_eq(local.op_b_val(), *local.op_b_access.prev_value());

        builder.constraint_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::C as u32),
            local.instruction.op_c[0],
            &local.op_c_access,
            AB::Expr::one() - local.selectors.imm_c,
        );
        builder
            .when_not(local.selectors.imm_c)
            .assert_word_eq(local.op_c_val(), *local.op_c_access.prev_value());

        // Write the `a` or the result to the first register described in the instruction unless
        // we are performing a branch or a store.
        // If we are writing to register 0, then the new value should be zero.
        builder
            .when(local.instruction.op_a_0)
            .assert_word_zero(*local.op_a_access.value());
        builder.constraint_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::A as u32),
            local.instruction.op_a[0],
            &local.op_a_access,
            local.is_real,
        );

        // If we are performing a branch or a store, then the value of `a` is the previous value.
        // Also, if op_a is register 0, then ensure that its value is 0.
        builder
            .when(is_branch_instruction.clone() + self.is_store_instruction::<AB>(&local.selectors))
            .assert_word_eq(local.op_a_val(), local.op_a_access.prev_value);

        // For operations that require reading from memory (not registers), we need to read the
        // value into the memory columns.
        let memory_columns = local.opcode_specific_columns.memory();
        builder.constraint_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            memory_columns.addr_aligned,
            &memory_columns.memory_access,
            is_memory_instruction.clone(),
        );

        // Check that reduce(addr_word) == addr_aligned + addr_offset.
        builder
            .when(is_memory_instruction.clone())
            .assert_eq::<AB::Expr, AB::Expr>(
                memory_columns.addr_aligned + memory_columns.addr_offset,
                memory_columns.addr_word.reduce::<AB>(),
            );

        // Check that each addr_word element is a byte.
        builder.slice_range_check_u8(
            &memory_columns.addr_word.0,
            local.shard,
            is_memory_instruction.clone(),
        );

        // Send to the ALU table to verify correct calculation of addr_word.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            memory_columns.addr_word,
            local.op_b_val(),
            local.op_c_val(),
            local.shard,
            is_memory_instruction.clone(),
        );

        // Memory handling.
        self.eval_memory_load::<AB>(builder, local);
        self.eval_memory_store::<AB>(builder, local);

        // Branch instructions.
        self.branch_ops_eval::<AB>(builder, is_branch_instruction.clone(), local, next);

        // Jump instructions.
        self.jump_ops_eval::<AB>(builder, local, next);

        // AUIPC instruction.
        self.auipc_eval(builder, local);

        // ECALL instruction.
        let (num_cycles, is_halt, is_commit) = self.ecall_eval(builder, local);

        builder.send_alu(
            local.instruction.opcode,
            local.op_a_val(),
            local.op_b_val(),
            local.op_c_val(),
            local.shard,
            is_alu_instruction,
        );

        self.shard_clk_eval(builder, local, next, &num_cycles);

        self.pc_eval(
            builder,
            local,
            next,
            is_branch_instruction.clone(),
            is_halt.clone(),
        );

        self.commit_eval(
            builder,
            local,
            is_commit,
            &public_values.committed_value_digest,
        );

        self.halt_unimpl_eval(builder, local, next, &is_halt);

        self.public_values_eval(builder, local, next, &public_values);

        // Check the is_real flag.  It should be 1 for the first row.  Once its 0, it should never
        // change value.
        builder.assert_bool(local.is_real);
        builder.when_first_row().assert_one(local.is_real);
        builder
            .when_transition()
            .when_not(local.is_real)
            .assert_zero(next.is_real);

        // Dummy constraint of degree 3.
        builder.assert_eq(
            local.pc * local.pc * local.pc,
            local.pc * local.pc * local.pc,
        );
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

    /// Whether the instruction is an ECALL instruction.
    pub(crate) fn is_ecall_instruction<AB: SP1AirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_ecall.into()
    }

    /// Constraints related to jump operations.
    pub(crate) fn jump_ops_eval<AB: SP1AirBuilder>(
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
    pub(crate) fn auipc_eval<AB: SP1AirBuilder>(&self, builder: &mut AB, local: &CpuCols<AB::Var>) {
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

    /// Constraints related to the ECALL opcode.
    pub(crate) fn ecall_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) -> (AB::Expr, AB::Expr, AB::Expr) {
        let ecall_cols = local.opcode_specific_columns.ecall();
        let is_ecall_instruction = self.is_ecall_instruction::<AB>(&local.selectors);
        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();
        // We interpret the syscall_code as little-endian bytes and interpret each byte as a u8
        // with different information. Read more about the format in runtime::syscall::SyscallCode.
        let syscall_id = syscall_code[0];
        let send_to_table = syscall_code[1]; // Does the syscall have a table that should be sent.
        let num_cycles = syscall_code[2]; // How many extra cycles to increment the clk for the syscall.

        // Check that the ecall_mul_send_to_table column is equal to send_to_table * is_ecall_instruction.
        // This is a separate column because it is used as a multiplicity in an interaction which
        // requires degree 1 columns.
        builder
            .when(is_ecall_instruction.clone())
            .assert_eq(send_to_table, local.ecall_mul_send_to_table);
        builder.send_syscall(
            local.shard,
            local.clk,
            syscall_id,
            local.op_b_val().reduce::<AB>(),
            local.op_c_val().reduce::<AB>(),
            local.ecall_mul_send_to_table,
        );

        // Constrain EcallCols.is_enter_unconstrained.result == syscall_id is ENTER_UNCONSTRAINED.
        let is_enter_unconstrained = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id
                    - AB::Expr::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
                ecall_cols.is_enter_unconstrained,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_enter_unconstrained.result
        };

        // Constrain EcallCols.is_halt.result == syscall_id is HALT.
        let is_halt = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_canonical_u32(SyscallCode::HALT.syscall_id()),
                ecall_cols.is_halt,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_halt.result
        };

        // Constrain EcallCols.is_hint_len.result == syscall_id is HINT_LEN.
        let is_hint_len = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
                ecall_cols.is_hint_len,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_hint_len.result
        };

        // Constrain EcallCols.is_commit.result == syscall_id is COMMIT.
        let is_commit = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
                ecall_cols.is_commit,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_commit.result
        };

        // When syscall_id is ENTER_UNCONSTRAINED, the new value of op_a should be 0.
        let zero_word = Word::<AB::F>::from(0);
        builder
            .when(is_ecall_instruction.clone() * is_enter_unconstrained)
            .assert_word_eq(local.op_a_val(), zero_word);

        // When the syscall is not one of ENTER_UNCONSTRAINED, HINT_LEN, or HALT, op_a shouldn't change.
        builder
            .when(is_ecall_instruction.clone())
            .when_not(is_enter_unconstrained + is_hint_len + is_halt)
            .assert_word_eq(local.op_a_val(), local.op_a_access.prev_value);

        (
            num_cycles * is_ecall_instruction.clone(),
            is_halt * is_ecall_instruction.clone(),
            is_commit * is_ecall_instruction,
        )
    }

    /// Constraints related to the shard and clk.
    ///
    /// This function ensures that all of the shard values are the same and that the clk starts at 0
    /// and is transitioned appropriately.  It will also check that shard values are within 16 bits
    /// and clk values are within 24 bits.  Those range checks are needed for the memory access
    /// timestamp check, which assumes those values are within 2^24.  See [`MemoryAirBuilder::verify_mem_access_ts`].
    pub(crate) fn shard_clk_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        num_cycles: &AB::Expr,
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
        let expected_next_clk = local.clk + AB::Expr::from_canonical_u32(4) + num_cycles.clone();

        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(expected_next_clk.clone(), next.clk);

        // Range check that the clk is within 24 bits using it's limb values.
        builder.verify_range_24bits(
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
    pub(crate) fn pc_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        is_branch_instruction: AB::Expr,
        is_halt: AB::Expr,
    ) {
        // Verify that if is_sequential_instr is true, assert that local.is_real is true.
        // This is needed for the following constraint, which is already degree 3.
        builder
            .when(local.is_sequential_instr)
            .assert_one(local.is_real);

        // When is_sequential_instr is true, assert that instruction is not branch, jump, or halt.
        // Note that the condition `when(local_is_real)` is implied from the previous constraint.
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

    /// Constraints related to the commit instruction.
    pub(crate) fn commit_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        is_commit: AB::Expr,
        commit_digest: &[Word<AB::Expr>; PV_DIGEST_NUM_WORDS],
    ) {
        // Get the ecall specific columns.
        let ecall_columns = local.opcode_specific_columns.ecall();

        // Verify the index bitmap.
        let mut bitmap_sum = AB::Expr::zero();
        for bit in ecall_columns.index_bitmap.iter() {
            builder.when(local.selectors.is_ecall).assert_bool(*bit);
            bitmap_sum += (*bit).into();
        }
        builder.when(is_commit.clone()).assert_one(bitmap_sum);

        // Retrieve the expected public values digest word to check against the one passed into the
        // commit ecall. Note that for the interaction builder, it will not have any digest words, since
        // it's used during AIR compilation time to parse for all send/receives. Since that interaction
        // builder will ignore the other constraints of the air, it is safe to not include the
        // verification check of the expected public values digest word.
        let expected_pv_digest_word =
            builder.index_word_array(commit_digest, &ecall_columns.index_bitmap);

        // Verify the public_values_digest_word.
        builder
            .when(is_commit)
            .assert_word_eq(expected_pv_digest_word, ecall_columns.digest_word);
    }

    /// Constraint related to the halt and unimpl instruction.
    pub(crate) fn halt_unimpl_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        is_halt: &AB::Expr,
    ) {
        // If we're halting and it's a transition, then the next.is_real should be 0.
        builder
            .when_transition()
            .when(is_halt.clone() + local.selectors.is_unimpl)
            .assert_zero(next.is_real);

        builder.when(is_halt.clone()).assert_zero(local.next_pc);
    }

    /// Constraint related to the public values.
    pub(crate) fn public_values_eval<AB: SP1AirBuilder>(
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
}

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}
