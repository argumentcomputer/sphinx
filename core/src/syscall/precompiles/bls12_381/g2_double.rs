use crate::air::{EventLens, MachineAir, WithEvents};
use crate::bytes::event::ByteRecord;
use crate::memory::{MemoryCols, MemoryWriteCols};
use crate::operations::field::extensions::quadratic::{QuadFieldOpCols, QuadFieldOperation};
use crate::operations::field::params::{FieldParameters, Limbs, WORDS_QUAD_EXT_CURVEPOINT};
use crate::runtime::{ExecutionRecord, MemoryWriteRecord, Syscall, SyscallCode, SyscallContext};
use crate::stark::SphinxAirBuilder;
use crate::utils::ec::weierstrass::bls12_381::{bls12381_double, Bls12381BaseField};
use crate::utils::{limbs_from_prev_access, pad_rows};
use crate::Program;
use core::borrow::{Borrow, BorrowMut};
use hybrid_array::{typenum::Unsigned, Array};
use num::{BigUint, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use serde::Deserialize;
use serde::Serialize;
use sphinx_derive::AlignedBorrow;
use std::mem::size_of;

/// Chip for doubling a BLS12-381 G2Affine point (P).
///
/// The algorithm used for computing the doubling inside the circuit doesn't require converting
/// input points to projective representation, however it has following unsupported corner cases:
///
/// - if P is point on infinity
///
#[derive(Default)]
pub struct Bls12381G2AffineDoubleChip;

impl Bls12381G2AffineDoubleChip {
    pub fn new() -> Self {
        Bls12381G2AffineDoubleChip
    }

    fn populate_field_ops<F: PrimeField32>(
        record: &mut impl ByteRecord,
        shard: u32,
        channel: u32,
        cols: &mut Bls12381G2AffineDoubleCols<F, Bls12381BaseField>,
        p_x: &[BigUint; 2],
        p_y: &[BigUint; 2],
    ) {
        // This populates necessary field operations to double a point on a Weierstrass curve.

        let a_const = &[BigUint::zero(), BigUint::zero()];
        let b_const = &[BigUint::from(3u32), BigUint::zero()];

        // slope = slope_numerator / slope_denominator.
        let slope = {
            // slope_numerator = a + (p.x * p.x) * 3.
            let slope_numerator = {
                let p_x_squared = cols.p_x_squared.populate(
                    record,
                    shard,
                    channel,
                    p_x,
                    p_x,
                    QuadFieldOperation::Mul,
                );

                let p_x_squared_times_3 = cols.p_x_squared_times_3.populate(
                    record,
                    shard,
                    channel,
                    &p_x_squared,
                    b_const,
                    QuadFieldOperation::Mul,
                );

                cols.slope_numerator.populate(
                    record,
                    shard,
                    channel,
                    a_const,
                    &p_x_squared_times_3,
                    QuadFieldOperation::Add,
                )
            };

            // slope_denominator = 2 * y.
            let slope_denominator = cols.slope_denominator.populate(
                record,
                shard,
                channel,
                p_y,
                p_y,
                QuadFieldOperation::Add,
            );

            cols.slope.populate(
                record,
                shard,
                channel,
                &slope_numerator,
                &slope_denominator,
                QuadFieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + p.x).
        let x = {
            let slope_squared = cols.slope_squared.populate(
                record,
                shard,
                channel,
                &slope,
                &slope,
                QuadFieldOperation::Mul,
            );
            let p_x_plus_p_x = cols.p_x_plus_p_x.populate(
                record,
                shard,
                channel,
                p_x,
                p_x,
                QuadFieldOperation::Add,
            );
            cols.x3_ins.populate(
                record,
                shard,
                channel,
                &slope_squared,
                &p_x_plus_p_x,
                QuadFieldOperation::Sub,
            )
        };

        // y = slope * (p.x - x) - p.y.
        {
            let p_x_minus_x =
                cols.p_x_minus_x
                    .populate(record, shard, channel, p_x, &x, QuadFieldOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate(
                record,
                shard,
                channel,
                &slope,
                &p_x_minus_x,
                QuadFieldOperation::Mul,
            );
            cols.y3_ins.populate(
                record,
                shard,
                channel,
                &slope_times_p_x_minus_x,
                p_y,
                QuadFieldOperation::Sub,
            )
        };
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bls12381G2AffineDoubleEvent {
    pub(crate) lookup_id: usize,
    clk: u32,
    shard: u32,
    channel: u32,
    p_ptr: u32,

    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    p_memory_records: Array<
        MemoryWriteRecord,
        WORDS_QUAD_EXT_CURVEPOINT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>,
    >,
    p_words: Vec<u32>,
}

impl Syscall for Bls12381G2AffineDoubleChip {
    fn execute(&self, ctx: &mut SyscallContext<'_, '_>, p_ptr: u32, _unused: u32) -> Option<u32> {
        let clk = ctx.clk;
        let shard = ctx.current_shard();
        let channel = ctx.current_channel();
        let lookup_id = ctx.syscall_lookup_id;

        assert_eq!(p_ptr % 4, 0, "arg1 ptr must be 4-byte aligned");

        let words_len =
            <WORDS_QUAD_EXT_CURVEPOINT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>>::USIZE;

        let p_words = ctx.slice_unsafe(p_ptr, words_len);

        let p_x_c0 = BigUint::new(p_words[0..12].to_vec());
        let p_x_c1 = BigUint::new(p_words[12..24].to_vec());
        let p_y_c0 = BigUint::new(p_words[24..36].to_vec());
        let p_y_c1 = BigUint::new(p_words[36..48].to_vec());

        let double = bls12381_double(&[p_x_c0, p_x_c1, p_y_c0, p_y_c1]);

        fn biguint_to_words(input: &BigUint) -> Vec<u32> {
            let mut result = input.to_u32_digits();
            // single Fp2 element in BLS12381 occupies 12 u32 words
            result.resize(12, 0);
            result
        }

        let double_words = [
            biguint_to_words(&double[0]),
            biguint_to_words(&double[1]),
            biguint_to_words(&double[2]),
            biguint_to_words(&double[3]),
        ]
        .concat();

        let p_memory_records: Array<
            MemoryWriteRecord,
            <Bls12381BaseField as FieldParameters>::NB_LIMBS,
        > = (&ctx.mw_slice(p_ptr, &double_words)[..])
            .try_into()
            .unwrap();

        ctx.record_mut()
            .bls12381_g2_double_events
            .push(Bls12381G2AffineDoubleEvent {
                lookup_id,
                clk,
                shard,
                channel,
                p_ptr,
                p_memory_records,
                p_words,
            });

        None
    }
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
struct Bls12381G2AffineDoubleCols<T, P: FieldParameters> {
    pub(crate) clk: T,
    pub(crate) shard: T,
    pub(crate) channel: T,
    pub(crate) nonce: T,
    pub(crate) is_real: T,

    pub(crate) p_ptr: T,
    pub(crate) p_access:
        Array<MemoryWriteCols<T>, <Bls12381BaseField as FieldParameters>::NB_LIMBS>,

    pub(crate) slope_denominator: QuadFieldOpCols<T, P>,
    pub(crate) slope_numerator: QuadFieldOpCols<T, P>,
    pub(crate) slope: QuadFieldOpCols<T, P>,
    pub(crate) p_x_squared: QuadFieldOpCols<T, P>,
    pub(crate) p_x_squared_times_3: QuadFieldOpCols<T, P>,
    pub(crate) slope_squared: QuadFieldOpCols<T, P>,
    pub(crate) p_x_plus_p_x: QuadFieldOpCols<T, P>,
    pub(crate) x3_ins: QuadFieldOpCols<T, P>,
    pub(crate) p_x_minus_x: QuadFieldOpCols<T, P>,
    pub(crate) y3_ins: QuadFieldOpCols<T, P>,
    pub(crate) slope_times_p_x_minus_x: QuadFieldOpCols<T, P>,
}

impl<T: PrimeField32> BaseAir<T> for Bls12381G2AffineDoubleChip {
    fn width(&self) -> usize {
        size_of::<Bls12381G2AffineDoubleCols<u8, Bls12381BaseField>>()
    }
}

impl<'a> WithEvents<'a> for Bls12381G2AffineDoubleChip {
    type Events = &'a [Bls12381G2AffineDoubleEvent];
}

impl<F: PrimeField32> MachineAir<F> for Bls12381G2AffineDoubleChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Bls12381G2AffineDoubleChip".to_string()
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        output: &mut Self::Record,
    ) -> RowMajorMatrix<F> {
        let mut rows: Vec<Vec<F>> = vec![];

        let width = <Bls12381G2AffineDoubleChip as BaseAir<F>>::width(self);

        let mut new_byte_lookup_events = Vec::new();

        for event in input.events() {
            let mut row = vec![F::zero(); width];
            let cols: &mut Bls12381G2AffineDoubleCols<F, Bls12381BaseField> =
                row.as_mut_slice().borrow_mut();

            cols.clk = F::from_canonical_u32(event.clk);
            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u32(event.channel);
            cols.p_ptr = F::from_canonical_u32(event.p_ptr);

            for index in 0..<Bls12381BaseField as FieldParameters>::NB_LIMBS::USIZE {
                cols.p_access[index].populate(
                    event.channel,
                    event.p_memory_records[index],
                    &mut new_byte_lookup_events,
                );
            }

            let p = &event.p_words;
            let p_x_c0 = BigUint::new(p[0..12].to_vec());
            let p_x_c1 = BigUint::new(p[12..24].to_vec());
            let p_y_c0 = BigUint::new(p[24..36].to_vec());
            let p_y_c1 = BigUint::new(p[36..48].to_vec());

            Self::populate_field_ops(
                &mut new_byte_lookup_events,
                event.shard,
                event.channel,
                cols,
                &[p_x_c0, p_x_c1],
                &[p_y_c0, p_y_c1],
            );

            rows.push(row);
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || {
            let mut row = vec![F::zero(); width];
            let cols: &mut Bls12381G2AffineDoubleCols<F, Bls12381BaseField> =
                row.as_mut_slice().borrow_mut();

            cols.clk = F::zero();
            cols.is_real = F::zero();
            cols.shard = F::zero();
            cols.channel = F::zero();
            cols.p_ptr = F::zero();

            let zero = BigUint::zero();
            Self::populate_field_ops(
                &mut vec![],
                0,
                0,
                cols,
                &[zero.clone(), zero.clone()],
                &[zero.clone(), zero.clone()],
            );

            row
        });

        let mut trace =
            RowMajorMatrix::<F>::new(rows.into_iter().flatten().collect::<Vec<_>>(), width);

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut Bls12381G2AffineDoubleCols<F, Bls12381BaseField> =
                trace.values[i * width..(i + 1) * width].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.bls12381_g2_double_events.is_empty()
    }
}

impl<AB: SphinxAirBuilder> Air<AB> for Bls12381G2AffineDoubleChip
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Bls12381G2AffineDoubleCols<AB::Var, Bls12381BaseField> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &Bls12381G2AffineDoubleCols<AB::Var, Bls12381BaseField> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        let a_const_limbs = &[
            Bls12381BaseField::to_limbs_field::<AB::F>(&BigUint::zero()),
            Bls12381BaseField::to_limbs_field::<AB::F>(&BigUint::zero()),
        ];

        let three_b_const_limbs = &[
            Bls12381BaseField::to_limbs_field::<AB::F>(&BigUint::from(3u32)),
            Bls12381BaseField::to_limbs_field::<AB::F>(&BigUint::zero()),
        ];

        let p_x_c0: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> =
            limbs_from_prev_access(&local.p_access[0..12]);
        let p_x_c1: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> =
            limbs_from_prev_access(&local.p_access[12..24]);
        let p_x = [p_x_c0, p_x_c1];

        let p_y_c0: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> =
            limbs_from_prev_access(&local.p_access[24..36]);
        let p_y_c1: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> =
            limbs_from_prev_access(&local.p_access[36..48]);
        let p_y = [p_y_c0, p_y_c1];

        // slope = slope_numerator / slope_denominator.
        let slope = {
            // slope_numerator = a + (p.x * p.x) * 3*b.
            {
                local.p_x_squared.eval(
                    builder,
                    &p_x,
                    &p_x,
                    QuadFieldOperation::Mul,
                    local.shard,
                    local.channel,
                    local.is_real,
                );

                local.p_x_squared_times_3.eval(
                    builder,
                    &local.p_x_squared.result,
                    three_b_const_limbs,
                    QuadFieldOperation::Mul,
                    local.shard,
                    local.channel,
                    local.is_real,
                );

                local.slope_numerator.eval(
                    builder,
                    a_const_limbs,
                    &local.p_x_squared_times_3.result,
                    QuadFieldOperation::Add,
                    local.shard,
                    local.channel,
                    local.is_real,
                );
            };

            // slope_denominator = 2 * y.
            local.slope_denominator.eval(
                builder,
                &p_y,
                &p_y,
                QuadFieldOperation::Add,
                local.shard,
                local.channel,
                local.is_real,
            );

            local.slope.eval(
                builder,
                &local.slope_numerator.result,
                &local.slope_denominator.result,
                QuadFieldOperation::Div,
                local.shard,
                local.channel,
                local.is_real,
            );

            local.slope.result
        };

        // x = slope * slope - (p.x + p.x).
        let x = {
            local.slope_squared.eval(
                builder,
                &slope,
                &slope,
                QuadFieldOperation::Mul,
                local.shard,
                local.channel,
                local.is_real,
            );
            local.p_x_plus_p_x.eval(
                builder,
                &p_x,
                &p_x,
                QuadFieldOperation::Add,
                local.shard,
                local.channel,
                local.is_real,
            );
            local.x3_ins.eval(
                builder,
                &local.slope_squared.result,
                &local.p_x_plus_p_x.result,
                QuadFieldOperation::Sub,
                local.shard,
                local.channel,
                local.is_real,
            );
            local.x3_ins.result
        };

        // y = slope * (p.x - x) - p.y.
        {
            local.p_x_minus_x.eval(
                builder,
                &p_x,
                &x,
                QuadFieldOperation::Sub,
                local.shard,
                local.channel,
                local.is_real,
            );
            local.slope_times_p_x_minus_x.eval(
                builder,
                &slope,
                &local.p_x_minus_x.result,
                QuadFieldOperation::Mul,
                local.shard,
                local.channel,
                local.is_real,
            );
            local.y3_ins.eval(
                builder,
                &local.slope_times_p_x_minus_x.result,
                &p_y,
                QuadFieldOperation::Sub,
                local.shard,
                local.channel,
                local.is_real,
            );
        }

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]. This is to
        // ensure that p_access is updated with the new value.
        let x3_ins_x = &local.x3_ins.result[0];
        let x3_ins_y = &local.x3_ins.result[1];
        let y3_ins_x = &local.y3_ins.result[0];
        let y3_ins_y = &local.y3_ins.result[1];
        for i in 0..<Bls12381BaseField as FieldParameters>::NB_LIMBS::USIZE {
            builder
                .when(local.is_real)
                .assert_eq(x3_ins_x[i], local.p_access[i / 4].value()[i % 4]);
            builder
                .when(local.is_real)
                .assert_eq(x3_ins_y[i], local.p_access[12 + i / 4].value()[i % 4]);
            builder
                .when(local.is_real)
                .assert_eq(y3_ins_x[i], local.p_access[24 + i / 4].value()[i % 4]);
            builder
                .when(local.is_real)
                .assert_eq(y3_ins_y[i], local.p_access[36 + i / 4].value()[i % 4]);
        }

        for index in 0..<Bls12381BaseField as FieldParameters>::NB_LIMBS::USIZE {
            builder.eval_memory_access(
                local.shard,
                local.channel,
                local.clk,
                local.p_ptr.into() + AB::F::from_canonical_u32((index as u32) * 4),
                &local.p_access[index],
                local.is_real,
            );
        }

        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::BLS12381_G2_DOUBLE.syscall_id()),
            local.p_ptr,
            AB::Expr::zero(),
            local.is_real,
        )
    }
}

#[allow(unused)] // Disabled for recursion performance
#[cfg(test)]
mod tests {
    use crate::runtime::{Instruction, Opcode, SyscallCode};
    use crate::stark::DefaultProver;
    use crate::utils::ec::weierstrass::bls12_381::fp_to_biguint;
    use crate::utils::tests::BLS12381_G2_DOUBLE_ELF;
    use crate::utils::{run_test, run_test_with_memory_inspection, setup_logger};
    use crate::Program;
    use bls12_381::G2Projective;
    use elliptic_curve::group::Curve;
    use elliptic_curve::Group;
    use num::{BigUint, Num};
    use rand::rngs::OsRng;

    fn biguint_to_words(input: &BigUint) -> Vec<u32> {
        let mut result = input.to_u32_digits();
        result.resize(12, 0);
        result
    }

    fn risc_v_program(p_ptr: u32, p_words: Vec<u32>) -> Program {
        let mut instructions = vec![];
        for (index, word) in p_words.into_iter().enumerate() {
            instructions.push(Instruction::new(Opcode::ADD, 29, 0, word, false, true));
            instructions.push(Instruction::new(
                Opcode::ADD,
                30,
                0,
                p_ptr + (index * 4) as u32,
                false,
                true,
            ));
            instructions.push(Instruction::new(Opcode::SW, 29, 30, 0, false, true));
        }

        instructions.push(Instruction::new(
            Opcode::ADD,
            5,
            0,
            SyscallCode::BLS12381_G2_DOUBLE as u32,
            false,
            true,
        ));
        instructions.push(Instruction::new(Opcode::ADD, 10, 0, p_ptr, false, true));
        instructions.push(Instruction::new(Opcode::ADD, 11, 0, 0, false, true));
        instructions.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false));
        Program::new(instructions, 0, 0)
    }

    fn execute_test(p_ptr: u32, p_value: &[BigUint; 4], expected: &[BigUint; 4]) {
        let words = [
            biguint_to_words(&p_value[0]),
            biguint_to_words(&p_value[1]),
            biguint_to_words(&p_value[2]),
            biguint_to_words(&p_value[3]),
        ]
        .concat();

        setup_logger();
        let program = risc_v_program(p_ptr, words);
        let (_, memory) = run_test_with_memory_inspection::<DefaultProver<_, _>>(program);

        let mut result = vec![];
        // Fp / BigUint is encoded as a 12 u32 words. G2Affine point has 4 Fp elements, so we read 4 * 12 words from the memory
        for i in 0..48 {
            result.push(memory.get(&(p_ptr + i * 4)).unwrap().value);
        }

        let computed_x_c0 = BigUint::new(result[0..12].to_vec());
        let computed_x_c1 = BigUint::new(result[12..24].to_vec());
        let computed_y_c0 = BigUint::new(result[24..36].to_vec());
        let computed_y_c1 = BigUint::new(result[36..48].to_vec());

        assert_eq!(computed_x_c0, expected[0]);
        assert_eq!(computed_x_c1, expected[1]);
        assert_eq!(computed_y_c0, expected[2]);
        assert_eq!(computed_y_c1, expected[3]);
    }

    // #[test]
    fn test_bls12381_g2_double_precompile() {
        let p_ptr = 100u32;
        let p = [
            BigUint::from_str_radix("00f0310692ee572076c940e7e486c4b3bcfa12d3aa83ce88ca53aca3d83cc388d10f7ab3dd58bc38b0dfc421a0741012", 16).unwrap(),
            BigUint::from_str_radix("05ba6e8828a638bdde01da90912664d74f4b97c526016a6c5ad517b717f0a76787c1576ce5748d7ebd5a052f7435ee9d", 16).unwrap(),
            BigUint::from_str_radix("18415e0e74a390dbaf7b1fe2408e0ff1d3a5ebf89d40ce374cfe625ad910da372670e13c4d1bf848cd261c9a17e20c5f", 16).unwrap(),
            BigUint::from_str_radix("149bc92f3dd4a1ea9da08fad7e8f97202f09b474eaa91624b27adcf9462f2ab2b6cc6c48b117241e9edb8fe8ed282de7", 16).unwrap(),
        ];
        let expected = [
            BigUint::from_str_radix("13e17a4d65e7935687da36118a193207e264f8c504a753da48236962d823902be0f2d3d8b1163b6b236a99b363074598", 16).unwrap(),
            BigUint::from_str_radix("af9ffb2d83cfd4c3d8448e5c313e494964f5ddc0165943488cd838a76175ed001fbd539bfd1162f5afbac5ca483faf1", 16).unwrap(),
            BigUint::from_str_radix("d62922919c99baf757b6d92cb4d5fe8595a93d79e5d7dfc39af35b2efd906faefb86df5cc5226a2d49b47934ef96070", 16).unwrap(),
            BigUint::from_str_radix("2d3a00fba534c8fe37bf850470209cf210f8502685536888e85cc8ad00bd64a29f03bff2a8c5952a87ac30f2ba8f6fa", 16).unwrap(),
        ];
        execute_test(p_ptr, &p, &expected);
    }

    // #[test]
    fn test_bls12381_g2_double_precompile_randomized_input() {
        let mut rng = OsRng;
        let p = G2Projective::random(&mut rng);
        let double_affine = p.double().to_affine();
        let p_affine = p.to_affine();

        let p_ptr = 100u32;

        let p = [
            fp_to_biguint(&p_affine.x.c0),
            fp_to_biguint(&p_affine.x.c1),
            fp_to_biguint(&p_affine.y.c0),
            fp_to_biguint(&p_affine.y.c1),
        ];

        let expected = [
            fp_to_biguint(&double_affine.x.c0),
            fp_to_biguint(&double_affine.x.c1),
            fp_to_biguint(&double_affine.y.c0),
            fp_to_biguint(&double_affine.y.c1),
        ];
        execute_test(p_ptr, &p, &expected);
    }

    // #[test]
    fn test_bls12381_g2_double_precompile_elf() {
        setup_logger();
        let program = Program::from(BLS12381_G2_DOUBLE_ELF);
        run_test::<DefaultProver<_, _>>(program).unwrap();
    }
}
