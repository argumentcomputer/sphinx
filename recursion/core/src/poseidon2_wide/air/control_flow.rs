use p3_air::AirBuilder;
use p3_field::AbstractField;
use sphinx_core::{air::BaseAirBuilder, operations::IsZeroOperation};

use crate::{
    air::SphinxRecursionAirBuilder,
    poseidon2_wide::{
        columns::{
            control_flow::ControlFlow, opcode_workspace::OpcodeWorkspace,
            syscall_params::SyscallParams, Poseidon2,
        },
        Poseidon2WideChip, RATE,
    },
    range_check::RangeCheckOpcode,
};

impl<F: Sync, const DEGREE: usize> Poseidon2WideChip<F, DEGREE> {
    /// Constraints related to control flow.
    pub(crate) fn eval_control_flow<AB: SphinxRecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_row: &dyn Poseidon2<'_, AB::Var>,
        next_row: &dyn Poseidon2<'_, AB::Var>,
        send_range_check: AB::Var,
    ) where
        AB::Var: 'static,
    {
        let local_control_flow = local_row.control_flow();
        let next_control_flow = next_row.control_flow();

        let local_is_real = local_control_flow.is_compress
            + local_control_flow.is_absorb
            + local_control_flow.is_finalize;
        let next_is_real = next_control_flow.is_compress
            + next_control_flow.is_absorb
            + next_control_flow.is_finalize;

        builder.assert_bool(local_control_flow.is_compress);
        builder.assert_bool(local_control_flow.is_compress_output);
        builder.assert_bool(local_control_flow.is_absorb);
        builder.assert_bool(local_control_flow.is_finalize);
        builder.assert_bool(local_control_flow.is_syscall_row);
        builder.assert_bool(local_is_real.clone());

        self.eval_global_control_flow(
            builder,
            local_control_flow,
            next_control_flow,
            local_row.syscall_params(),
            next_row.syscall_params(),
            local_row.opcode_workspace(),
            next_row.opcode_workspace(),
            &local_is_real,
            &next_is_real,
        );

        self.eval_hash_control_flow(
            builder,
            local_control_flow,
            local_row.opcode_workspace(),
            next_row.opcode_workspace(),
            local_row.syscall_params(),
            send_range_check,
        );
    }

    /// This function will verify that all hash rows are before the compress rows and that the first
    /// row is the first absorb syscall.  These constraints will require that there is at least one
    /// absorb, finalize, and compress system call.
    #[allow(clippy::too_many_arguments)]
    fn eval_global_control_flow<AB: SphinxRecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_control_flow: &ControlFlow<AB::Var>,
        next_control_flow: &ControlFlow<AB::Var>,
        local_syscall_params: &SyscallParams<AB::Var>,
        next_syscall_params: &SyscallParams<AB::Var>,
        local_opcode_workspace: &OpcodeWorkspace<AB::Var>,
        next_opcode_workspace: &OpcodeWorkspace<AB::Var>,
        local_is_real: &AB::Expr,
        next_is_real: &AB::Expr,
    ) {
        // We require that the first row is an absorb syscall and that the hash_num == 0.
        let mut first_row_builder = builder.when_first_row();
        first_row_builder.assert_one(local_control_flow.is_absorb);
        first_row_builder.assert_one(local_control_flow.is_syscall_row);
        first_row_builder.assert_zero(local_syscall_params.absorb().hash_num);
        first_row_builder.assert_one(local_opcode_workspace.absorb().is_first_hash_row);

        let mut transition_builder = builder.when_transition();

        // For absorb rows, constrain the following:
        // 1) next row is either an absorb or syscall finalize.
        // 2) when last absorb row, then the next row is a syscall row.
        // 2) hash_num == hash_num'.
        {
            let mut absorb_transition_builder =
                transition_builder.when(local_control_flow.is_absorb);
            absorb_transition_builder
                .assert_one(next_control_flow.is_absorb + next_control_flow.is_finalize);
            absorb_transition_builder
                .when(local_opcode_workspace.absorb().is_last_row::<AB>())
                .assert_one(next_control_flow.is_syscall_row);

            absorb_transition_builder
                .when(next_control_flow.is_absorb)
                .assert_eq(
                    local_syscall_params.absorb().hash_num,
                    next_syscall_params.absorb().hash_num,
                );
            absorb_transition_builder
                .when(next_control_flow.is_finalize)
                .assert_eq(
                    local_syscall_params.absorb().hash_num,
                    next_syscall_params.finalize().hash_num,
                );
        }

        // For finalize rows, constrain the following:
        // 1) next row is syscall compress or syscall absorb.
        // 2) if next row is absorb -> hash_num + 1 == hash_num'
        // 3) if next row is absorb -> is_first_hash' == true
        {
            let mut finalize_transition_builder =
                transition_builder.when(local_control_flow.is_finalize);

            finalize_transition_builder
                .assert_one(next_control_flow.is_absorb + next_control_flow.is_compress);
            finalize_transition_builder.assert_one(next_control_flow.is_syscall_row);

            finalize_transition_builder
                .when(next_control_flow.is_absorb)
                .assert_eq(
                    local_syscall_params.finalize().hash_num + AB::Expr::one(),
                    next_syscall_params.absorb().hash_num,
                );
            finalize_transition_builder
                .when(next_control_flow.is_absorb)
                .assert_one(next_opcode_workspace.absorb().is_first_hash_row);
        }

        // For compress rows, constrain the following:
        // 1) if compress syscall -> next row is a compress output
        // 2) if compress output -> next row is a compress syscall or not real
        {
            transition_builder
                .when(local_control_flow.is_compress)
                .when(local_control_flow.is_syscall_row)
                .assert_one(next_control_flow.is_compress_output);

            transition_builder
                .when(local_control_flow.is_compress_output)
                .assert_one(
                    next_control_flow.is_compress + (AB::Expr::one() - next_is_real.clone()),
                );

            transition_builder
                .when(local_control_flow.is_compress_output)
                .when(next_control_flow.is_compress)
                .assert_one(next_control_flow.is_syscall_row);
        }

        // Constrain that there is only one is_real -> not is real transition.  Also contrain that
        // the last real row is a compress output row.
        {
            transition_builder
                .when_not(local_is_real.clone())
                .assert_zero(next_is_real.clone());

            transition_builder
                .when(local_is_real.clone())
                .when_not(next_is_real.clone())
                .assert_one(local_control_flow.is_compress_output);

            builder
                .when_last_row()
                .when(local_is_real.clone())
                .assert_one(local_control_flow.is_compress_output);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_hash_control_flow<AB: SphinxRecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_control_flow: &ControlFlow<AB::Var>,
        local_opcode_workspace: &OpcodeWorkspace<AB::Var>,
        next_opcode_workspace: &OpcodeWorkspace<AB::Var>,
        local_syscall_params: &SyscallParams<AB::Var>,
        send_range_check: AB::Var,
    ) {
        let local_hash_workspace = local_opcode_workspace.absorb();
        let next_hash_workspace = next_opcode_workspace.absorb();
        let last_row_ending_cursor_is_seven =
            local_hash_workspace.last_row_ending_cursor_is_seven.result;

        // Constrain the materialized control flow flags.
        {
            let mut absorb_builder = builder.when(local_control_flow.is_absorb);

            absorb_builder.assert_eq(
                local_hash_workspace.is_syscall_not_last_row,
                local_control_flow.is_syscall_row
                    * (AB::Expr::one() - local_hash_workspace.is_last_row::<AB>()),
            );
            absorb_builder.assert_eq(
                local_hash_workspace.not_syscall_not_last_row,
                (AB::Expr::one() - local_control_flow.is_syscall_row)
                    * (AB::Expr::one() - local_hash_workspace.is_last_row::<AB>()),
            );
            absorb_builder.assert_eq(
                local_hash_workspace.is_syscall_is_last_row,
                local_control_flow.is_syscall_row * local_hash_workspace.is_last_row::<AB>(),
            );
            absorb_builder.assert_eq(
                local_hash_workspace.not_syscall_is_last_row,
                (AB::Expr::one() - local_control_flow.is_syscall_row)
                    * local_hash_workspace.is_last_row::<AB>(),
            );
            absorb_builder.assert_eq(
                local_hash_workspace.is_last_row_ending_cursor_is_seven,
                local_hash_workspace.is_last_row::<AB>() * last_row_ending_cursor_is_seven,
            );
            absorb_builder.assert_eq(
                local_hash_workspace.is_last_row_ending_cursor_not_seven,
                local_hash_workspace.is_last_row::<AB>()
                    * (AB::Expr::one() - last_row_ending_cursor_is_seven),
            );

            builder.assert_eq(
                local_control_flow.is_absorb_not_last_row,
                local_control_flow.is_absorb
                    * (AB::Expr::one() - local_hash_workspace.is_last_row::<AB>()),
            );

            builder.assert_eq(
                local_control_flow.is_absorb_no_perm,
                local_control_flow.is_absorb
                    * (AB::Expr::one() - local_hash_workspace.do_perm::<AB>()),
            )
        }

        // For the absorb syscall row, ensure correct value of num_remaining_rows, last_row_num_consumed,
        // and num_remaining_rows_is_zero.
        {
            let mut absorb_builder = builder.when(local_control_flow.is_absorb);

            // Verify that state_cursor + syscall input_len - 1 == num_remaining_rows * RATE + last_row_ending_cursor.
            // The minus one is needed, since `last_row_ending_cursor` is inclusive of the last element,
            // while state_cursor + syscall input_len is not.
            absorb_builder
                .when(local_control_flow.is_syscall_row)
                .assert_eq(
                    local_hash_workspace.state_cursor + local_syscall_params.absorb().input_len
                        - AB::Expr::one(),
                    local_hash_workspace.num_remaining_rows * AB::Expr::from_canonical_usize(RATE)
                        + local_hash_workspace.last_row_ending_cursor,
                );

            // Range check that last_row_ending_cursor is between [0, 7].
            (0..3).for_each(|i| {
                absorb_builder.assert_bool(local_hash_workspace.last_row_ending_cursor_bitmap[i])
            });
            let expected_last_row_ending_cursor: AB::Expr = local_hash_workspace
                .last_row_ending_cursor_bitmap
                .iter()
                .zip(0..3)
                .map(|(bit, exp)| *bit * AB::Expr::from_canonical_u32(2u32.pow(exp)))
                .sum::<AB::Expr>();
            absorb_builder
                .when(local_control_flow.is_syscall_row)
                .assert_eq(
                    local_hash_workspace.last_row_ending_cursor,
                    expected_last_row_ending_cursor,
                );

            // Range check that num_remaining_rows is between [0, 2^18-1].
            builder.send_range_check(
                AB::Expr::from_canonical_u8(RangeCheckOpcode::U16 as u8),
                local_hash_workspace.num_remaining_rows,
                send_range_check,
            );
        }

        // For all non last absorb rows, verify that num_remaining_rows decrements and
        // that last_row_ending_cursor is copied down.
        {
            let mut transition_builder = builder.when_transition();
            let mut absorb_transition_builder =
                transition_builder.when(local_control_flow.is_absorb);

            absorb_transition_builder
                .when_not(local_hash_workspace.is_last_row::<AB>())
                .assert_eq(
                    next_hash_workspace.num_remaining_rows,
                    local_hash_workspace.num_remaining_rows - AB::Expr::one(),
                );

            // Copy down the last_row_ending_cursor value within the absorb call.
            absorb_transition_builder
                .when_not(local_hash_workspace.is_last_row::<AB>())
                .assert_eq(
                    next_hash_workspace.last_row_ending_cursor,
                    local_hash_workspace.last_row_ending_cursor,
                );
        }

        // Constrain the state cursor.  There are three constraints:
        // 1) For the first hash row, verify that state_cursor == 0.
        // 2) For the last absorb rows, verify that constrain
        //    state_cursor' = (last_row_ending_cursor + 1) % RATE.
        // 3) For all non syscall rows, the state_cursor should be 0.
        {
            let mut absorb_builder = builder.when(local_control_flow.is_absorb);

            absorb_builder
                .when(local_hash_workspace.is_first_hash_row)
                .assert_zero(local_hash_workspace.state_cursor);

            absorb_builder
                .when(local_hash_workspace.is_last_row_ending_cursor_is_seven)
                .assert_zero(next_hash_workspace.state_cursor);

            absorb_builder
                .when(local_hash_workspace.is_last_row_ending_cursor_not_seven)
                .assert_eq(
                    next_hash_workspace.state_cursor,
                    local_hash_workspace.last_row_ending_cursor + AB::Expr::one(),
                );

            absorb_builder
                .when_not(local_control_flow.is_syscall_row)
                .assert_zero(local_hash_workspace.state_cursor);
        }

        // Eval the absorb's iszero operations.
        {
            // Drop absorb_builder so that builder can be used in the IsZeroOperation eval.
            IsZeroOperation::<AB::F>::eval(
                builder,
                local_hash_workspace.last_row_ending_cursor - AB::Expr::from_canonical_usize(7),
                local_hash_workspace.last_row_ending_cursor_is_seven,
                local_control_flow.is_absorb.into(),
            );

            IsZeroOperation::<AB::F>::eval(
                builder,
                local_hash_workspace.num_remaining_rows.into(),
                local_hash_workspace.num_remaining_rows_is_zero,
                local_control_flow.is_absorb.into(),
            );
        }

        // Apply control flow constraints for finalize.
        {
            // Eval state_cursor_is_zero.
            IsZeroOperation::<AB::F>::eval(
                builder,
                local_opcode_workspace.finalize().state_cursor.into(),
                local_opcode_workspace.finalize().state_cursor_is_zero,
                local_control_flow.is_finalize.into(),
            );
        }
    }
}
