use core::borrow::Borrow;
use core::mem::size_of;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use wp1_core::air::{BaseAirBuilder, ExtensionAirBuilder, SP1AirBuilder};
use wp1_primitives::RC_16_30_U32;

use crate::air::{RecursionInteractionAirBuilder, RecursionMemoryAirBuilder};
use crate::poseidon2_wide::{apply_m_4, internal_linear_layer};
use crate::runtime::Opcode;

use super::columns::Poseidon2Cols;

/// The number of main trace columns for `AddChip`.
pub(crate) const NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2Cols<u8>>();

/// The width of the permutation.
pub(crate) const WIDTH: usize = 16;

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct Poseidon2Chip {
    pub fixed_log2_rows: Option<usize>,
}

impl<F> BaseAir<F> for Poseidon2Chip {
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS
    }
}

impl Poseidon2Chip {
    pub fn eval_poseidon2<AB: BaseAirBuilder + ExtensionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2Cols<AB::Var>,
    ) {
        let rounds_f = 8;
        let rounds_p = 13;
        let rounds_p_beginning = 2 + rounds_f / 2;
        let rounds_p_end = rounds_p_beginning + rounds_p;

        let is_memory_read = local.rounds[0];
        let is_initial = local.rounds[1];

        // First half of the external rounds.
        let mut is_external_layer = (2..rounds_p_beginning)
            .map(|i| local.rounds[i].into())
            .sum::<AB::Expr>();

        // Second half of the external rounds.
        is_external_layer += (rounds_p_end..rounds_p + rounds_f)
            .map(|i| local.rounds[i].into())
            .sum::<AB::Expr>();
        let is_internal_layer = (rounds_p_beginning..rounds_p_end)
            .map(|i| local.rounds[i].into())
            .sum::<AB::Expr>();
        let is_memory_write = local.rounds[local.rounds.len() - 1];

        self.eval_mem(builder, local, is_memory_read, is_memory_write);

        self.eval_computation(
            builder,
            local,
            &is_initial.into(),
            &is_external_layer,
            is_internal_layer.clone(),
            rounds_f + rounds_p + 1,
        );

        self.eval_syscall(builder, local);

        // Range check all flags.
        for i in 0..local.rounds.len() {
            builder.assert_bool(local.rounds[i]);
        }
        builder.assert_bool(
            is_memory_read + is_initial + is_external_layer + is_internal_layer + is_memory_write,
        );
    }

    fn eval_mem<AB: BaseAirBuilder + ExtensionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2Cols<AB::Var>,
        is_memory_read: AB::Var,
        is_memory_write: AB::Var,
    ) {
        let memory_access_cols = local.round_specific_cols.memory_access();

        builder
            .when(is_memory_read)
            .assert_eq(local.left_input, memory_access_cols.addr_first_half);
        builder
            .when(is_memory_read)
            .assert_eq(local.right_input, memory_access_cols.addr_second_half);

        builder
            .when(is_memory_write)
            .assert_eq(local.dst_input, memory_access_cols.addr_first_half);
        builder.when(is_memory_write).assert_eq(
            local.dst_input + AB::F::from_canonical_usize(4),
            memory_access_cols.addr_second_half,
        );

        for i in 0..WIDTH {
            let addr = if i < WIDTH / 2 {
                memory_access_cols.addr_first_half + AB::Expr::from_canonical_usize(i)
            } else {
                memory_access_cols.addr_second_half + AB::Expr::from_canonical_usize(i - WIDTH / 2)
            };
            builder.recursion_eval_memory_access_single(
                local.timestamp,
                addr,
                &memory_access_cols.mem_access[i],
                is_memory_read + is_memory_write,
            );
        }
    }

    fn eval_computation<AB: BaseAirBuilder + ExtensionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2Cols<AB::Var>,
        is_initial: &AB::Expr,
        is_external_layer: &AB::Expr,
        is_internal_layer: AB::Expr,
        rounds: usize,
    ) {
        let computation_cols = local.round_specific_cols.computation();

        // Convert the u32 round constants to field elements.
        let constants: [[AB::F; WIDTH]; 30] =
            RC_16_30_U32.map(|round| round.map(AB::F::from_wrapped_u32));

        // Apply the round constants.
        //
        // Initial Layer: Don't apply the round constants.
        // External Layers: Apply the round constants.
        // Internal Layers: Only apply the round constants to the first element.
        for i in 0..WIDTH {
            let mut result: AB::Expr = computation_cols.input[i].into();
            for r in 0..rounds {
                if i == 0 {
                    result += local.rounds[r + 1]
                        * constants[r][i]
                        * (is_external_layer.clone() + is_internal_layer.clone());
                } else {
                    result += local.rounds[r + 1] * constants[r][i] * is_external_layer.clone();
                }
            }
            builder
                .when(is_initial.clone() + is_external_layer.clone() + is_internal_layer.clone())
                .assert_eq(result, computation_cols.add_rc[i]);
        }

        // Apply the sbox.
        //
        // To differentiate between external and internal layers, we use a masking operation
        // to only apply the state change to the first element for internal layers.
        for i in 0..WIDTH {
            let sbox_deg_3 = computation_cols.add_rc[i]
                * computation_cols.add_rc[i]
                * computation_cols.add_rc[i];
            builder
                .when(is_initial.clone() + is_external_layer.clone() + is_internal_layer.clone())
                .assert_eq(sbox_deg_3, computation_cols.sbox_deg_3[i]);
            let sbox_deg_7 = computation_cols.sbox_deg_3[i]
                * computation_cols.sbox_deg_3[i]
                * computation_cols.add_rc[i];
            builder
                .when(is_initial.clone() + is_external_layer.clone() + is_internal_layer.clone())
                .assert_eq(sbox_deg_7, computation_cols.sbox_deg_7[i]);
        }
        let sbox_result: [AB::Expr; WIDTH] = computation_cols
            .sbox_deg_7
            .iter()
            .enumerate()
            .map(|(i, x)| {
                // The masked first result of the sbox.
                //
                // Initial Layer: Pass through the result of the round constant layer.
                // External Layer: Pass through the result of the sbox layer.
                // Internal Layer: Pass through the result of the sbox layer.
                if i == 0 {
                    is_initial.clone() * computation_cols.add_rc[i]
                        + (is_external_layer.clone() + is_internal_layer.clone()) * *x
                }
                // The masked result of the rest of the sbox.
                //
                // Initial layer: Pass through the result of the round constant layer.
                // External layer: Pass through the result of the sbox layer.
                // Internal layer: Pass through the result of the round constant layer.
                else {
                    (is_initial.clone() + is_internal_layer.clone()) * computation_cols.add_rc[i]
                        + (is_external_layer.clone()) * *x
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // EXTERNAL LAYER + INITIAL LAYER
        {
            // First, we apply M_4 to each consecutive four elements of the state.
            // In Appendix B's terminology, this replaces each x_i with x_i'.
            let mut state: [AB::Expr; WIDTH] = sbox_result.clone();
            for i in (0..WIDTH).step_by(4) {
                apply_m_4(&mut state[i..i + 4]);
            }

            // Now, we apply the outer circulant matrix (to compute the y_i values).
            //
            // We first precompute the four sums of every four elements.
            let sums: [AB::Expr; 4] = core::array::from_fn(|k| {
                (0..WIDTH)
                    .step_by(4)
                    .map(|j| state[j + k].clone())
                    .sum::<AB::Expr>()
            });

            // The formula for each y_i involves 2x_i' term and x_j' terms for each j that equals i mod 4.
            // In other words, we can add a single copy of x_i' to the appropriate one of our precomputed sums.
            for i in 0..WIDTH {
                state[i] += sums[i % 4].clone();
                builder
                    .when(is_external_layer.clone() + is_initial.clone())
                    .assert_eq(state[i].clone(), computation_cols.output[i]);
            }
        }

        // INTERNAL LAYER
        {
            // Use a simple matrix multiplication as the permutation.
            let mut state: [AB::Expr; WIDTH] = sbox_result.clone();
            internal_linear_layer(&mut state);
            builder
                .when(is_internal_layer)
                .assert_all_eq(state.clone(), computation_cols.output);
        }
    }

    fn eval_syscall<AB: BaseAirBuilder + ExtensionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2Cols<AB::Var>,
    ) {
        // Constraint that the operands are sent from the CPU table.
        let operands: [AB::Expr; 4] = [
            local.timestamp.into(),
            local.dst_input.into(),
            local.left_input.into(),
            local.right_input.into(),
        ];
        builder.receive_table(
            Opcode::Poseidon2Compress.as_field::<AB::F>(),
            &operands,
            local.rounds[0],
        );
    }
}

impl<AB> Air<AB> for Poseidon2Chip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2Cols<AB::Var> = (*local).borrow();
        self.eval_poseidon2::<AB>(builder, local);
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use std::borrow::Borrow;
    use std::time::Instant;

    use p3_baby_bear::BabyBear;
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::AbstractField;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use p3_poseidon2::Poseidon2;
    use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
    use wp1_core::stark::StarkGenericConfig;
    use wp1_core::utils::inner_perm;
    use wp1_core::{
        air::MachineAir,
        utils::{uni_stark_prove, uni_stark_verify, BabyBearPoseidon2},
    };

    use crate::{
        poseidon2::{Poseidon2Chip, Poseidon2Event, WIDTH},
        runtime::ExecutionRecord,
    };
    use p3_symmetric::Permutation;

    use super::Poseidon2Cols;

    const ROWS_PER_PERMUTATION: usize = 24;

    #[test]
    #[ignore = "broken in upstream, will be fixed by https://github.com/succinctlabs/sp1/pull/672"]
    fn generate_trace() {
        let chip = Poseidon2Chip {
            fixed_log2_rows: None,
        };
        let test_inputs = vec![
            [BabyBear::from_canonical_u32(1); WIDTH],
            [BabyBear::from_canonical_u32(2); WIDTH],
            [BabyBear::from_canonical_u32(3); WIDTH],
            [BabyBear::from_canonical_u32(4); WIDTH],
        ];

        let gt: Poseidon2<
            BabyBear,
            Poseidon2ExternalMatrixGeneral,
            DiffusionMatrixBabyBear,
            16,
            7,
        > = inner_perm();

        let expected_outputs = test_inputs
            .iter()
            .map(|input| gt.permute(*input))
            .collect::<Vec<_>>();

        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for (input, output) in test_inputs.into_iter().zip_eq(expected_outputs.clone()) {
            input_exec
                .poseidon2_events
                .push(Poseidon2Event::dummy_from_input(input, output));
        }

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());

        for (i, expected_output) in expected_outputs.iter().enumerate() {
            let row = trace.row(ROWS_PER_PERMUTATION * (i + 1) - 2).collect_vec();
            let cols: &Poseidon2Cols<BabyBear> = row.as_slice().borrow();
            let computation_cols = cols.round_specific_cols.computation();
            assert_eq!(expected_output, &computation_cols.output);
        }
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::compressed();
        let mut challenger = config.challenger();

        let chip = Poseidon2Chip {
            fixed_log2_rows: None,
        };

        let test_inputs = (0..16)
            .map(|i| [BabyBear::from_canonical_u32(i); WIDTH])
            .collect_vec();

        let gt: Poseidon2<
            BabyBear,
            Poseidon2ExternalMatrixGeneral,
            DiffusionMatrixBabyBear,
            16,
            7,
        > = inner_perm();

        let expected_outputs = test_inputs
            .iter()
            .map(|input| gt.permute(*input))
            .collect::<Vec<_>>();

        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for (input, output) in test_inputs.into_iter().zip_eq(expected_outputs) {
            input_exec
                .poseidon2_events
                .push(Poseidon2Event::dummy_from_input(input, output));
        }
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
        println!(
            "trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        let start = Instant::now();
        let proof = uni_stark_prove(&config, &chip, &mut challenger, trace);
        let duration = start.elapsed().as_secs_f64();
        println!("proof duration = {:?}", duration);

        let mut challenger: p3_challenger::DuplexChallenger<
            BabyBear,
            Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
            16,
        > = config.challenger();
        let start = Instant::now();
        uni_stark_verify(&config, &chip, &mut challenger, &proof)
            .expect("expected proof to be valid");

        let duration = start.elapsed().as_secs_f64();
        println!("verify duration = {:?}", duration);
    }
}
