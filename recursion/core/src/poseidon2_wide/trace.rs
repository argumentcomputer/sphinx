use std::borrow::Borrow;

use p3_air::BaseAir;
use p3_field::PrimeField32;
#[allow(unused_imports)]
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sphinx_core::air::{EventLens, WithEvents};
use sphinx_core::{air::MachineAir, utils::pad_rows_fixed};
use sphinx_primitives::RC_16_30_U32;
use tracing::instrument;

use crate::poseidon2_wide::columns::permutation::permutation_mut;
use crate::poseidon2_wide::events::Poseidon2HashEvent;
use crate::range_check::{RangeCheckEvent, RangeCheckOpcode};
use crate::{
    poseidon2_wide::{external_linear_layer, NUM_EXTERNAL_ROUNDS, WIDTH},
    runtime::{ExecutionRecord, RecursionProgram},
};

use super::events::{Poseidon2AbsorbEvent, Poseidon2CompressEvent, Poseidon2FinalizeEvent};
use super::RATE;
use super::{internal_linear_layer, Poseidon2WideChip, NUM_INTERNAL_ROUNDS};

impl<'a, F: 'a + Sync, const DEGREE: usize> WithEvents<'a> for Poseidon2WideChip<F, DEGREE> {
    type Events = (&'a [Poseidon2HashEvent<F>], &'a [Poseidon2CompressEvent<F>]);
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for Poseidon2WideChip<F, DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        format!("Poseidon2Wide {}", DEGREE)
    }

    #[instrument(name = "generate poseidon2 wide trace", level = "debug", skip_all, fields(rows = input.events().1.len()))]
    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let num_columns = <Poseidon2WideChip<F, DEGREE> as BaseAir<F>>::width(self);
        let (hash_events, compress_events) = input.events();

        // Populate the hash events.
        for event in hash_events {
            match event {
                Poseidon2HashEvent::Absorb(absorb_event) => {
                    rows.extend(self.populate_absorb_event(absorb_event, num_columns, output));
                }

                Poseidon2HashEvent::Finalize(finalize_event) => {
                    rows.push(self.populate_finalize_event(finalize_event, num_columns));
                }
            }
        }

        // Populate the compress events.
        for event in compress_events {
            rows.extend(self.populate_compress_event(event, num_columns));
        }

        if self.pad {
            // Pad the trace to a power of two.
            pad_rows_fixed(
                &mut rows,
                || {
                    let mut padded_row = vec![F::zero(); num_columns];
                    self.populate_permutation([F::zero(); WIDTH], None, &mut padded_row);
                    padded_row
                },
                self.fixed_log2_rows,
            );
        }

        // Convert the trace to a row major matrix.
        let trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), num_columns);

        #[cfg(debug_assertions)]
        println!(
            "poseidon2 wide trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        trace
    }

    fn included(&self, record: &Self::Record) -> bool {
        !record.poseidon2_compress_events.is_empty()
    }
}

impl<F: PrimeField32, const DEGREE: usize> Poseidon2WideChip<F, DEGREE> {
    pub fn populate_compress_event(
        &self,
        compress_event: &Poseidon2CompressEvent<F>,
        num_columns: usize,
    ) -> Vec<Vec<F>> {
        let mut compress_rows = Vec::new();

        let mut input_row = vec![F::zero(); num_columns];
        // Populate the control flow fields.
        {
            let mut cols = self.convert_mut(&mut input_row);
            let control_flow = cols.control_flow_mut();

            control_flow.is_compress = F::one();
            control_flow.is_syscall_row = F::one();
        }

        // Populate the syscall params fields.
        {
            let mut cols = self.convert_mut(&mut input_row);
            let syscall_params = cols.syscall_params_mut().compress_mut();

            syscall_params.clk = compress_event.clk;
            syscall_params.dst_ptr = compress_event.dst;
            syscall_params.left_ptr = compress_event.left;
            syscall_params.right_ptr = compress_event.right;
        }

        // Populate the memory fields.
        {
            let mut cols = self.convert_mut(&mut input_row);
            let memory = cols.memory_mut();

            memory.start_addr = compress_event.left;
            // Populate the first half of the memory inputs in the memory struct.
            for i in 0..WIDTH / 2 {
                memory.memory_slot_used[i] = F::one();
                memory.memory_accesses[i].populate(&compress_event.input_records[i]);
            }
        }

        // Populate the opcode workspace fields.
        {
            let mut cols = self.convert_mut(&mut input_row);
            let compress_cols = cols.opcode_workspace_mut().compress_mut();
            compress_cols.start_addr = compress_event.right;

            // Populate the second half of the memory inputs.
            for i in 0..WIDTH / 2 {
                compress_cols.memory_accesses[i]
                    .populate(&compress_event.input_records[i + WIDTH / 2]);
            }
        }

        // Populate the permutation fields.
        self.populate_permutation(
            compress_event.input,
            Some(compress_event.result_array),
            &mut input_row,
        );

        compress_rows.push(input_row);

        let mut output_row = vec![F::zero(); num_columns];
        {
            let mut cols = self.convert_mut(&mut output_row);
            let control_flow = cols.control_flow_mut();

            control_flow.is_compress = F::one();
            control_flow.is_compress_output = F::one();
        }

        {
            let mut cols = self.convert_mut(&mut output_row);
            let syscall_cols = cols.syscall_params_mut().compress_mut();

            syscall_cols.clk = compress_event.clk;
            syscall_cols.dst_ptr = compress_event.dst;
            syscall_cols.left_ptr = compress_event.left;
            syscall_cols.right_ptr = compress_event.right;
        }

        {
            let mut cols = self.convert_mut(&mut output_row);
            let memory = cols.memory_mut();

            memory.start_addr = compress_event.dst;
            // Populate the first half of the memory inputs in the memory struct.
            for i in 0..WIDTH / 2 {
                memory.memory_slot_used[i] = F::one();
                memory.memory_accesses[i].populate(&compress_event.result_records[i]);
            }
        }

        {
            let mut cols = self.convert_mut(&mut output_row);
            let compress_cols = cols.opcode_workspace_mut().compress_mut();

            compress_cols.start_addr = compress_event.dst + F::from_canonical_usize(WIDTH / 2);
            for i in 0..WIDTH / 2 {
                compress_cols.memory_accesses[i]
                    .populate(&compress_event.result_records[i + WIDTH / 2]);
            }
        }

        self.populate_permutation(compress_event.result_array, None, &mut output_row);

        compress_rows.push(output_row);
        compress_rows
    }

    pub fn populate_absorb_event(
        &self,
        absorb_event: &Poseidon2AbsorbEvent<F>,
        num_columns: usize,
        output: &mut ExecutionRecord<F>,
    ) -> Vec<Vec<F>> {
        let mut absorb_rows = Vec::new();

        // We currently don't support an input_len of 0, since it will need special logic in the AIR.
        assert!(absorb_event.input_len > F::zero());

        let mut last_row_ending_cursor = 0;
        let num_absorb_rows = absorb_event.iterations.len();

        for (iter_num, absorb_iter) in absorb_event.iterations.iter().enumerate() {
            let mut absorb_row = vec![F::zero(); num_columns];
            let is_syscall_row = iter_num == 0;
            let is_last_row = iter_num == num_absorb_rows - 1;

            // Populate the control flow fields.
            {
                let mut cols = self.convert_mut(&mut absorb_row);
                let control_flow = cols.control_flow_mut();

                control_flow.is_absorb = F::one();
                control_flow.is_syscall_row = F::from_bool(is_syscall_row);
                control_flow.is_absorb_no_perm = F::from_bool(!absorb_iter.do_perm);
                control_flow.is_absorb_not_last_row = F::from_bool(!is_last_row);
            }

            // Populate the syscall params fields.
            {
                let mut cols = self.convert_mut(&mut absorb_row);
                let syscall_params = cols.syscall_params_mut().absorb_mut();

                syscall_params.clk = absorb_event.clk;
                syscall_params.hash_num = absorb_event.hash_num;
                syscall_params.input_ptr = absorb_event.input_addr;
                syscall_params.input_len = absorb_event.input_len;
            }

            // Populate the memory fields.
            {
                let mut cols = self.convert_mut(&mut absorb_row);
                let memory = cols.memory_mut();

                memory.start_addr = absorb_iter.start_addr;
                for (i, input_record) in absorb_iter.input_records.iter().enumerate() {
                    memory.memory_slot_used[i + absorb_iter.state_cursor] = F::one();
                    memory.memory_accesses[i + absorb_iter.state_cursor].populate(input_record);
                }
            }

            // Populate the opcode workspace fields.
            {
                let mut cols = self.convert_mut(&mut absorb_row);
                let absorb_workspace = cols.opcode_workspace_mut().absorb_mut();

                let num_remaining_rows = num_absorb_rows - 1 - iter_num;
                absorb_workspace.num_remaining_rows = F::from_canonical_usize(num_remaining_rows);
                output.add_range_check_events(&[RangeCheckEvent::new(
                    RangeCheckOpcode::U16,
                    num_remaining_rows as u16,
                )]);

                // Calculate last_row_num_consumed.
                // For absorb calls that span multiple rows (e.g. the last row is not the syscall row),
                // last_row_num_consumed = (input_len + state_cursor) % 8 at the syscall row.
                // For absorb calls that are only one row, last_row_num_consumed = absorb_event.input_len.
                if is_syscall_row {
                    last_row_ending_cursor = (absorb_iter.state_cursor
                        + absorb_event.input_len.as_canonical_u32() as usize
                        - 1)
                        % RATE;
                }

                absorb_workspace.last_row_ending_cursor =
                    F::from_canonical_usize(last_row_ending_cursor);

                absorb_workspace
                    .last_row_ending_cursor_is_seven
                    .populate_from_field_element(
                        F::from_canonical_usize(last_row_ending_cursor)
                            - F::from_canonical_usize(7),
                    );

                (0..3).for_each(|i| {
                    absorb_workspace.last_row_ending_cursor_bitmap[i] =
                        F::from_bool((last_row_ending_cursor) & (1 << i) == (1 << i))
                });

                absorb_workspace
                    .num_remaining_rows_is_zero
                    .populate(num_remaining_rows as u32);

                absorb_workspace.is_syscall_not_last_row =
                    F::from_bool(is_syscall_row && !is_last_row);
                absorb_workspace.is_syscall_is_last_row =
                    F::from_bool(is_syscall_row && is_last_row);
                absorb_workspace.not_syscall_not_last_row =
                    F::from_bool(!is_syscall_row && !is_last_row);
                absorb_workspace.not_syscall_is_last_row =
                    F::from_bool(!is_syscall_row && is_last_row);
                absorb_workspace.is_last_row_ending_cursor_is_seven =
                    F::from_bool(is_last_row && last_row_ending_cursor == 7);
                absorb_workspace.is_last_row_ending_cursor_not_seven =
                    F::from_bool(is_last_row && last_row_ending_cursor != 7);

                absorb_workspace.state = absorb_iter.state;
                absorb_workspace.previous_state = absorb_iter.previous_state;
                absorb_workspace.state_cursor = F::from_canonical_usize(absorb_iter.state_cursor);
                absorb_workspace.is_first_hash_row =
                    F::from_bool(iter_num == 0 && absorb_event.is_first_aborb);

                absorb_workspace.start_mem_idx_bitmap[absorb_iter.state_cursor] = F::one();
                if is_last_row {
                    absorb_workspace.end_mem_idx_bitmap[last_row_ending_cursor] = F::one();
                }
            }

            // Populate the permutation fields.
            self.populate_permutation(
                absorb_iter.perm_input,
                if absorb_iter.do_perm {
                    Some(absorb_iter.perm_output)
                } else {
                    None
                },
                &mut absorb_row,
            );

            absorb_rows.push(absorb_row);
        }

        absorb_rows
    }

    pub fn populate_finalize_event(
        &self,
        finalize_event: &Poseidon2FinalizeEvent<F>,
        num_columns: usize,
    ) -> Vec<F> {
        let mut finalize_row = vec![F::zero(); num_columns];

        // Populate the control flow fields.
        {
            let mut cols = self.convert_mut(&mut finalize_row);
            let control_flow = cols.control_flow_mut();
            control_flow.is_finalize = F::one();
            control_flow.is_syscall_row = F::one();
        }

        // Populate the syscall params fields.
        {
            let mut cols = self.convert_mut(&mut finalize_row);

            let syscall_params = cols.syscall_params_mut().finalize_mut();
            syscall_params.clk = finalize_event.clk;
            syscall_params.hash_num = finalize_event.hash_num;
            syscall_params.output_ptr = finalize_event.output_ptr;
        }

        // Populate the memory fields.
        {
            let mut cols = self.convert_mut(&mut finalize_row);
            let memory = cols.memory_mut();

            memory.start_addr = finalize_event.output_ptr;
            for i in 0..WIDTH / 2 {
                memory.memory_slot_used[i] = F::one();
                memory.memory_accesses[i].populate(&finalize_event.output_records[i]);
            }
        }

        // Populate the opcode workspace fields.
        {
            let mut cols = self.convert_mut(&mut finalize_row);
            let finalize_workspace = cols.opcode_workspace_mut().finalize_mut();

            finalize_workspace.previous_state = finalize_event.previous_state;
            finalize_workspace.state = finalize_event.state;
            finalize_workspace.state_cursor = F::from_canonical_usize(finalize_event.state_cursor);
            finalize_workspace
                .state_cursor_is_zero
                .populate(finalize_event.state_cursor as u32);
        }

        // Populate the permutation fields.
        self.populate_permutation(
            finalize_event.perm_input,
            if finalize_event.do_perm {
                Some(finalize_event.perm_output)
            } else {
                None
            },
            &mut finalize_row,
        );

        finalize_row
    }

    pub fn populate_permutation(
        &self,
        input: [F; WIDTH],
        expected_output: Option<[F; WIDTH]>,
        input_row: &mut [F],
    ) {
        let mut permutation = permutation_mut::<F, DEGREE>(input_row);

        let (
            external_rounds_state,
            internal_rounds_state,
            internal_rounds_s0,
            mut external_sbox,
            mut internal_sbox,
            output_state,
        ) = permutation.get_cols_mut();

        external_rounds_state[0] = input;
        external_linear_layer(&mut external_rounds_state[0]);

        // Apply the first half of external rounds.
        for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
            let next_state =
                self.populate_external_round(external_rounds_state, &mut external_sbox, r);
            if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
                *internal_rounds_state = next_state;
            } else {
                external_rounds_state[r + 1] = next_state;
            }
        }

        // Apply the internal rounds.
        external_rounds_state[NUM_EXTERNAL_ROUNDS / 2] = self.populate_internal_rounds(
            internal_rounds_state,
            internal_rounds_s0,
            &mut internal_sbox,
        );

        // Apply the second half of external rounds.
        for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
            let next_state =
                self.populate_external_round(external_rounds_state, &mut external_sbox, r);
            if r == NUM_EXTERNAL_ROUNDS - 1 {
                for i in 0..WIDTH {
                    output_state[i] = next_state[i];
                    if let Some(expected_output) = expected_output {
                        assert_eq!(expected_output[i], next_state[i]);
                    }
                }
            } else {
                external_rounds_state[r + 1] = next_state;
            }
        }
    }

    fn populate_external_round(
        &self,
        external_rounds_state: &[[F; WIDTH]],
        sbox: &mut Option<&mut [[F; WIDTH]; NUM_EXTERNAL_ROUNDS]>,
        r: usize,
    ) -> [F; WIDTH] {
        let mut state = {
            let round_state: &[F; WIDTH] = external_rounds_state[r].borrow();

            // Add round constants.
            //
            // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
            // columns for it, and instead include it in the constraint for the x^3 part of the sbox.
            let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
                r
            } else {
                r + NUM_INTERNAL_ROUNDS
            };
            let mut add_rc = *round_state;
            #[allow(clippy::needless_range_loop)]
            for i in 0..WIDTH {
                add_rc[i] += F::from_wrapped_u32(RC_16_30_U32[round][i]);
            }

            // Apply the sboxes.
            // Optimization: since the linear layer that comes after the sbox is degree 1, we can
            // avoid adding columns for the result of the sbox, and instead include the x^3 -> x^7
            // part of the sbox in the constraint for the linear layer
            let mut sbox_deg_7: [F; 16] = [F::zero(); WIDTH];
            let mut sbox_deg_3: [F; 16] = [F::zero(); WIDTH];
            for i in 0..WIDTH {
                sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
                sbox_deg_7[i] = sbox_deg_3[i] * sbox_deg_3[i] * add_rc[i];
            }

            if let Some(sbox) = sbox.as_deref_mut() {
                sbox[r] = sbox_deg_3;
            }

            sbox_deg_7
        };

        // Apply the linear layer.
        external_linear_layer(&mut state);
        state
    }

    fn populate_internal_rounds(
        &self,
        internal_rounds_state: &[F; WIDTH],
        internal_rounds_s0: &mut [F; NUM_INTERNAL_ROUNDS - 1],
        sbox: &mut Option<&mut [F; NUM_INTERNAL_ROUNDS]>,
    ) -> [F; WIDTH] {
        let mut state: [F; WIDTH] = *internal_rounds_state;
        let mut sbox_deg_3: [F; NUM_INTERNAL_ROUNDS] = [F::zero(); NUM_INTERNAL_ROUNDS];
        for r in 0..NUM_INTERNAL_ROUNDS {
            // Add the round constant to the 0th state element.
            // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
            // columns for it, just like for external rounds.
            let round = r + NUM_EXTERNAL_ROUNDS / 2;
            let add_rc = state[0] + F::from_wrapped_u32(RC_16_30_U32[round][0]);

            // Apply the sboxes.
            // Optimization: since the linear layer that comes after the sbox is degree 1, we can
            // avoid adding columns for the result of the sbox, just like for external rounds.
            sbox_deg_3[r] = add_rc * add_rc * add_rc;
            let sbox_deg_7 = sbox_deg_3[r] * sbox_deg_3[r] * add_rc;

            // Apply the linear layer.
            state[0] = sbox_deg_7;
            internal_linear_layer(&mut state);

            // Optimization: since we're only applying the sbox to the 0th state element, we only
            // need to have columns for the 0th state element at every step. This is because the
            // linear layer is degree 1, so all state elements at the end can be expressed as a
            // degree-3 polynomial of the state at the beginning of the internal rounds and the 0th
            // state element at rounds prior to the current round
            if r < NUM_INTERNAL_ROUNDS - 1 {
                internal_rounds_s0[r] = state[0];
            }
        }

        let ret_state = state;

        if let Some(sbox) = sbox.as_deref_mut() {
            *sbox = sbox_deg_3;
        }

        ret_state
    }
}
