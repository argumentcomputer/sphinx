use p3_air::AirBuilder;
use p3_field::AbstractField;

use crate::air::{AluAirBuilder, BaseAirBuilder, MemoryAirBuilder, Word, WordAirBuilder};
use crate::cpu::columns::{CpuCols, MemoryColumns, OpcodeSelectorCols};
use crate::cpu::CpuChip;
use crate::memory::MemoryCols;
use crate::runtime::{MemoryAccessPosition, Opcode};

impl CpuChip {
    /// Computes whether the opcode is a memory instruction.
    pub(crate) fn is_memory_instruction<AB: BaseAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_lb
            + opcode_selectors.is_lbu
            + opcode_selectors.is_lh
            + opcode_selectors.is_lhu
            + opcode_selectors.is_lw
            + opcode_selectors.is_sb
            + opcode_selectors.is_sh
            + opcode_selectors.is_sw
    }

    /// Computes whether the opcode is a load instruction.
    pub(crate) fn is_load_instruction<AB: BaseAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_lb
            + opcode_selectors.is_lbu
            + opcode_selectors.is_lh
            + opcode_selectors.is_lhu
            + opcode_selectors.is_lw
    }

    /// Computes whether the opcode is a store instruction.
    pub(crate) fn is_store_instruction<AB: BaseAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_sb + opcode_selectors.is_sh + opcode_selectors.is_sw
    }

    /// Constrains the addr_aligned, addr_offset, and addr_word memory columns.
    ///
    /// This method will do the following:
    /// 1. Calculate that the unaligned address is correctly computed to be op_b.value + op_c.value.
    /// 2. Calculate that the address offset is address % 4.
    /// 3. Assert the validity of the aligned address given the address offset and the unaligned address.
    pub(crate) fn eval_memory_address_and_access<AB: MemoryAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        is_memory_instruction: &AB::Expr,
    ) {
        // Get the memory specific columns.
        let memory_columns = local.opcode_specific_columns.memory();

        // Send to the ALU table to verify correct calculation of addr_word.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            memory_columns.addr_word,
            local.op_b_val(),
            local.op_c_val(),
            local.shard,
            local.channel,
            is_memory_instruction.clone(),
        );

        // Check that each addr_word element is a byte.
        builder.slice_range_check_u8(
            &memory_columns.addr_word.0,
            local.shard,
            local.channel,
            is_memory_instruction.clone(),
        );

        // Evaluate the addr_offset column and offset flags.
        self.eval_offset_value_flags(builder, memory_columns, local);

        // Assert that reduce(addr_word) == addr_aligned + addr_offset.
        builder
            .when(is_memory_instruction.clone())
            .assert_eq::<AB::Expr, AB::Expr>(
                memory_columns.addr_aligned + memory_columns.addr_offset,
                memory_columns.addr_word.reduce::<AB>(),
            );

        // For operations that require reading from memory (not registers), we need to read the
        // value into the memory columns.
        builder.eval_memory_access(
            local.shard,
            local.channel,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            memory_columns.addr_aligned,
            &memory_columns.memory_access,
            is_memory_instruction.clone(),
        );
    }

    /// Evaluates constraints related to loading from memory.
    pub(crate) fn eval_memory_load<AB: AluAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) {
        // Get the memory specific columns.
        let memory_columns = local.opcode_specific_columns.memory();

        // Compute whether this is a load instruction.
        let is_load = self.is_load_instruction::<AB>(&local.selectors);

        // Verify the unsigned_mem_value column.
        self.eval_unsigned_mem_value(builder, memory_columns, local);

        // If it's a signed operation (such as LB or LH), then we need verify the bit decomposition
        // of the most significant byte to get it's sign.
        self.eval_most_sig_byte_bit_decomp(builder, memory_columns, local, &local.unsigned_mem_val);

        // Assert that if `is_lb` and `is_lh` are both true, then the most significant byte
        // matches the value of `local.mem_value_is_neg`.
        builder
            .when(local.selectors.is_lb + local.selectors.is_lh)
            .assert_eq(
                local.mem_value_is_neg,
                memory_columns.most_sig_byte_decomp[7],
            );

        // When the memory value is negative, use the SUB opcode to compute the signed value of
        // the memory value and verify that the op_a value is correct.
        let signed_value = Word([
            AB::Expr::zero(),
            AB::Expr::one() * local.selectors.is_lb,
            AB::Expr::one() * local.selectors.is_lh,
            AB::Expr::zero(),
        ]);
        builder.send_alu(
            Opcode::SUB.as_field::<AB::F>(),
            local.op_a_val(),
            local.unsigned_mem_val,
            signed_value,
            local.shard,
            local.channel,
            local.mem_value_is_neg,
        );

        // When the memory value is not negaitve, assert that op_a value is equal to the unsigned
        // memory value.
        builder
            .when(is_load)
            .when_not(local.mem_value_is_neg)
            .assert_word_eq(local.unsigned_mem_val, local.op_a_val());
    }

    /// Evaluates constraints related to storing to memory.
    pub(crate) fn eval_memory_store<AB: BaseAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) {
        let memory_columns = local.opcode_specific_columns.memory();

        // Get the memory offset flags.
        self.eval_offset_value_flags(builder, memory_columns, local);
        // Compute the offset_is_zero flag.  The other offset flags are already constrained by the
        // method `eval_memory_address_and_access`, which is called in `eval_memory_address_and_access`.
        let offset_is_zero = AB::Expr::one()
            - memory_columns.offset_is_one
            - memory_columns.offset_is_two
            - memory_columns.offset_is_three;

        // Compute the expected stored value for a SB instruction.
        let one = AB::Expr::one();
        let a_val = local.op_a_val();
        let mem_val = *memory_columns.memory_access.value();
        let prev_mem_val = *memory_columns.memory_access.prev_value();
        let sb_expected_stored_value = Word([
            a_val[0] * offset_is_zero.clone()
                + (one.clone() - offset_is_zero.clone()) * prev_mem_val[0],
            a_val[0] * memory_columns.offset_is_one
                + (one.clone() - memory_columns.offset_is_one) * prev_mem_val[1],
            a_val[0] * memory_columns.offset_is_two
                + (one.clone() - memory_columns.offset_is_two) * prev_mem_val[2],
            a_val[0] * memory_columns.offset_is_three
                + (one.clone() - memory_columns.offset_is_three) * prev_mem_val[3],
        ]);
        builder
            .when(local.selectors.is_sb)
            .assert_word_eq(mem_val.map(|x| x.into()), sb_expected_stored_value);

        // When the instruction is SH, make sure both offset one and three are off.
        builder
            .when(local.selectors.is_sh)
            .assert_zero(memory_columns.offset_is_one + memory_columns.offset_is_three);

        // Compute the expected stored value for a SH instruction.
        let a_is_lower_half = offset_is_zero;
        let a_is_upper_half = memory_columns.offset_is_two;
        let sh_expected_stored_value = Word([
            a_val[0] * a_is_lower_half.clone()
                + (one.clone() - a_is_lower_half.clone()) * prev_mem_val[0],
            a_val[1] * a_is_lower_half.clone() + (one.clone() - a_is_lower_half) * prev_mem_val[1],
            a_val[0] * a_is_upper_half + (one.clone() - a_is_upper_half) * prev_mem_val[2],
            a_val[1] * a_is_upper_half + (one.clone() - a_is_upper_half) * prev_mem_val[3],
        ]);
        builder
            .when(local.selectors.is_sh)
            .assert_word_eq(mem_val.map(|x| x.into()), sh_expected_stored_value);

        // When the instruction is SW, just use the word without masking.
        builder
            .when(local.selectors.is_sw)
            .assert_word_eq(mem_val.map(|x| x.into()), a_val.map(|x| x.into()));
    }

    /// This function is used to evaluate the unsigned memory value for the load memory instructions.
    pub(crate) fn eval_unsigned_mem_value<AB: BaseAirBuilder>(
        &self,
        builder: &mut AB,
        memory_columns: &MemoryColumns<AB::Var>,
        local: &CpuCols<AB::Var>,
    ) {
        let mem_val = *memory_columns.memory_access.value();

        // Compute the offset_is_zero flag.  The other offset flags are already constrained by the
        // method `eval_memory_address_and_access`, which is called in `eval_memory_address_and_access`.
        let offset_is_zero = AB::Expr::one()
            - memory_columns.offset_is_one
            - memory_columns.offset_is_two
            - memory_columns.offset_is_three;

        // Compute the byte value.
        let mem_byte = mem_val[0] * offset_is_zero.clone()
            + mem_val[1] * memory_columns.offset_is_one
            + mem_val[2] * memory_columns.offset_is_two
            + mem_val[3] * memory_columns.offset_is_three;
        let byte_value = Word::extend_expr::<AB>(mem_byte.clone());

        // When the instruction is LB or LBU, just use the lower byte.
        builder
            .when(local.selectors.is_lb + local.selectors.is_lbu)
            .assert_word_eq(byte_value, local.unsigned_mem_val.map(|x| x.into()));

        // When the instruction is LH or LHU, use the lower half.
        builder
            .when(local.selectors.is_lh + local.selectors.is_lhu)
            .assert_zero(memory_columns.offset_is_one + memory_columns.offset_is_three);
        let use_lower_half = offset_is_zero;
        let use_upper_half = memory_columns.offset_is_two;
        let half_value = Word([
            use_lower_half.clone() * mem_val[0] + use_upper_half * mem_val[2],
            use_lower_half * mem_val[1] + use_upper_half * mem_val[3],
            AB::Expr::zero(),
            AB::Expr::zero(),
        ]);
        builder
            .when(local.selectors.is_lh + local.selectors.is_lhu)
            .assert_word_eq(half_value, local.unsigned_mem_val.map(|x| x.into()));

        // When the instruction is LW, just use the word.
        builder
            .when(local.selectors.is_lw)
            .assert_word_eq(mem_val, local.unsigned_mem_val);
    }

    /// Evaluates the decomposition of the most significant byte of the memory value.
    pub(crate) fn eval_most_sig_byte_bit_decomp<AB: BaseAirBuilder>(
        &self,
        builder: &mut AB,
        memory_columns: &MemoryColumns<AB::Var>,
        local: &CpuCols<AB::Var>,
        unsigned_mem_val: &Word<AB::Var>,
    ) {
        let mut recomposed_byte = AB::Expr::zero();
        for i in 0..8 {
            builder.assert_bool(memory_columns.most_sig_byte_decomp[i]);
            recomposed_byte +=
                memory_columns.most_sig_byte_decomp[i] * AB::Expr::from_canonical_u8(1 << i);
        }
        builder
            .when(local.selectors.is_lb)
            .assert_eq(recomposed_byte.clone(), unsigned_mem_val[0]);
        builder
            .when(local.selectors.is_lh)
            .assert_eq(recomposed_byte, unsigned_mem_val[1]);
    }

    /// Evaluates the offset value flags.
    pub(crate) fn eval_offset_value_flags<AB: BaseAirBuilder>(
        &self,
        builder: &mut AB,
        memory_columns: &MemoryColumns<AB::Var>,
        local: &CpuCols<AB::Var>,
    ) {
        let is_mem_op = self.is_memory_instruction::<AB>(&local.selectors);
        let offset_is_zero = AB::Expr::one()
            - memory_columns.offset_is_one
            - memory_columns.offset_is_two
            - memory_columns.offset_is_three;

        let mut filtered_builder = builder.when(is_mem_op);

        // Assert that the value flags are boolean
        filtered_builder.assert_bool(memory_columns.offset_is_one);
        filtered_builder.assert_bool(memory_columns.offset_is_two);
        filtered_builder.assert_bool(memory_columns.offset_is_three);

        // Assert that only one of the value flags is true
        filtered_builder.assert_one(
            offset_is_zero.clone()
                + memory_columns.offset_is_one
                + memory_columns.offset_is_two
                + memory_columns.offset_is_three,
        );

        // Assert that the correct value flag is set
        filtered_builder
            .when(offset_is_zero)
            .assert_zero(memory_columns.addr_offset);
        filtered_builder
            .when(memory_columns.offset_is_one)
            .assert_one(memory_columns.addr_offset);
        filtered_builder
            .when(memory_columns.offset_is_two)
            .assert_eq(memory_columns.addr_offset, AB::Expr::two());
        filtered_builder
            .when(memory_columns.offset_is_three)
            .assert_eq(memory_columns.addr_offset, AB::Expr::from_canonical_u8(3));
    }
}
