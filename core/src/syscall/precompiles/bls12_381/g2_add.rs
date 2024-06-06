use crate::air::{
    AluAirBuilder, EventLens, EventMutLens, MachineAir, MemoryAirBuilder, WithEvents,
};
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::memory::{MemoryCols, MemoryReadCols, MemoryWriteCols};
use crate::operations::field::extensions::quadratic::{QuadFieldOpCols, QuadFieldOperation};
use crate::operations::field::params::{FieldParameters, WORDS_QUAD_EXT_CURVEPOINT};
use crate::operations::field::params::{Limbs, WORDS_QUAD_EXT_FIELD_ELEMENT};
use crate::runtime::{
    ExecutionRecord, MemoryReadRecord, MemoryWriteRecord, Syscall, SyscallCode, SyscallContext,
};
use crate::utils::ec::weierstrass::bls12_381::{bls12381_g2_add, Bls12381BaseField};
use crate::utils::ec::AffinePoint;
use crate::utils::{limbs_from_access, limbs_from_prev_access, pad_vec_rows};
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

/// Chip for adding to BLS12-381 G2Affine points (A and B).
///
/// The algorithm used for computing the addition inside the circuit doesn't require converting
/// input points to projective representation, however it has following unsupported corner cases:
///
/// - if A is point on infinity,
/// - if B is point on infinity,
/// - if A equals B,
/// - if A equals -B.
///
#[derive(Default)]
pub struct Bls12381G2AffineAddChip;

impl Bls12381G2AffineAddChip {
    pub fn new() -> Self {
        Self {}
    }

    fn populate_cols<F: PrimeField32>(
        record: &mut impl ByteRecord,
        shard: u32,
        cols: &mut Bls12381G2AffineAddCols<F, Bls12381BaseField>,
        a_x: &[BigUint; 2],
        a_y: &[BigUint; 2],
        b_x: &[BigUint; 2],
        b_y: &[BigUint; 2],
    ) {
        let slope = {
            let slope_numerator = cols.slope_numerator.populate(
                record,
                shard,
                &[b_y[0].clone(), b_y[1].clone()],
                &[a_y[0].clone(), a_y[1].clone()],
                QuadFieldOperation::Sub,
            );

            let slope_denominator = cols.slope_denominator.populate(
                record,
                shard,
                &[b_x[0].clone(), b_x[1].clone()],
                &[a_x[0].clone(), a_x[1].clone()],
                QuadFieldOperation::Sub,
            );

            cols.slope.populate(
                record,
                shard,
                &slope_numerator,
                &slope_denominator,
                QuadFieldOperation::Div,
            )
        };

        let x = {
            let slope_squared =
                cols.slope_squared
                    .populate(record, shard, &slope, &slope, QuadFieldOperation::Mul);
            let p_x_plus_q_x = cols.p_x_plus_q_x.populate(
                record,
                shard,
                &[a_x[0].clone(), a_x[1].clone()],
                &[b_x[0].clone(), b_x[1].clone()],
                QuadFieldOperation::Add,
            );
            cols.x3_ins.populate(
                record,
                shard,
                &slope_squared,
                &p_x_plus_q_x,
                QuadFieldOperation::Sub,
            )
        };

        {
            let p_x_minus_x = cols.p_x_minus_x.populate(
                record,
                shard,
                &[a_x[0].clone(), a_x[1].clone()],
                &x,
                QuadFieldOperation::Sub,
            );
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate(
                record,
                shard,
                &slope,
                &p_x_minus_x,
                QuadFieldOperation::Mul,
            );
            cols.y3_ins.populate(
                record,
                shard,
                &slope_times_p_x_minus_x,
                &[a_y[0].clone(), a_y[1].clone()],
                QuadFieldOperation::Sub,
            )
        };
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bls12381G2AffineAddEvent {
    pub clk: u32,
    pub shard: u32,
    pub a_ptr: u32,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub a_x:
        Array<u32, WORDS_QUAD_EXT_FIELD_ELEMENT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub a_y:
        Array<u32, WORDS_QUAD_EXT_FIELD_ELEMENT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub b_x:
        Array<u32, WORDS_QUAD_EXT_FIELD_ELEMENT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub b_y:
        Array<u32, WORDS_QUAD_EXT_FIELD_ELEMENT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>>,

    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub a_memory_records: Array<
        MemoryWriteRecord,
        WORDS_QUAD_EXT_CURVEPOINT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>,
    >,
    pub b_ptr: u32,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub b_memory_records: Array<
        MemoryReadRecord,
        WORDS_QUAD_EXT_CURVEPOINT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>,
    >,
}

impl Syscall for Bls12381G2AffineAddChip {
    fn execute(&self, ctx: &mut SyscallContext<'_>, a_ptr: u32, b_ptr: u32) -> Option<u32> {
        let clk = ctx.clk;
        let shard = ctx.current_shard();

        assert_eq!(a_ptr % 4, 0, "arg1 ptr must be 4-byte aligned");
        assert_eq!(b_ptr % 4, 0, "arg2 ptr must be 4-byte aligned");

        let words_len =
            <WORDS_QUAD_EXT_CURVEPOINT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>>::USIZE;

        let a_vec = ctx.slice_unsafe(a_ptr, words_len);
        let (b_memory_records, b_vec) = ctx.mr_slice(b_ptr, words_len);

        let a_x: Array<
            u32,
            WORDS_QUAD_EXT_FIELD_ELEMENT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>,
        > = (&a_vec[0..words_len / 2]).try_into().unwrap();
        let a_y: Array<
            u32,
            WORDS_QUAD_EXT_FIELD_ELEMENT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>,
        > = (&a_vec[words_len / 2..words_len]).try_into().unwrap();
        let b_x: Array<
            u32,
            WORDS_QUAD_EXT_FIELD_ELEMENT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>,
        > = (&b_vec[0..words_len / 2]).try_into().unwrap();
        let b_y: Array<
            u32,
            WORDS_QUAD_EXT_FIELD_ELEMENT<<Bls12381BaseField as FieldParameters>::NB_LIMBS>,
        > = (&b_vec[words_len / 2..words_len]).try_into().unwrap();

        let a_x_c0 = BigUint::new(a_x[0..12].to_vec());
        let a_x_c1 = BigUint::new(a_x[12..24].to_vec());
        let a_y_c0 = BigUint::new(a_y[0..12].to_vec());
        let a_y_c1 = BigUint::new(a_y[12..24].to_vec());

        let b_x_c0 = BigUint::new(b_x[0..12].to_vec());
        let b_x_c1 = BigUint::new(b_x[12..24].to_vec());
        let b_y_c0 = BigUint::new(b_y[0..12].to_vec());
        let b_y_c1 = BigUint::new(b_y[12..24].to_vec());

        let result = bls12381_g2_add(
            &[a_x_c0, a_x_c1, a_y_c0, a_y_c1],
            &[b_x_c0, b_x_c1, b_y_c0, b_y_c1],
        );

        fn biguint_to_words(input: &BigUint) -> Vec<u32> {
            let mut words = input.to_u32_digits();
            // single Fp2 element in BLS12381 occupies 12 u32 words
            words.resize(12, 0);
            words
        }

        let result_words = [
            biguint_to_words(&result[0]),
            biguint_to_words(&result[1]),
            biguint_to_words(&result[2]),
            biguint_to_words(&result[3]),
        ]
        .concat();

        // When we write to p, we want the clk to be incremented because p and q could be the same.
        ctx.clk += 1;

        let a_memory_records: Array<
            MemoryWriteRecord,
            <Bls12381BaseField as FieldParameters>::NB_LIMBS,
        > = (&ctx.mw_slice(a_ptr, &result_words)[..])
            .try_into()
            .unwrap();

        ctx.record_mut()
            .bls12381_g2_add_events
            .push(Bls12381G2AffineAddEvent {
                clk,
                shard,
                a_ptr,
                a_x,
                a_y,
                b_x,
                b_y,
                a_memory_records,
                b_ptr,
                b_memory_records: (&b_memory_records[..]).try_into().unwrap(),
            });

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Bls12381G2AffineAddCols<T, P: FieldParameters> {
    pub clk: T,
    pub shard: T,
    pub is_real: T,

    pub a_ptr: T,
    pub a_access: Array<MemoryWriteCols<T>, <Bls12381BaseField as FieldParameters>::NB_LIMBS>,
    pub b_ptr: T,
    pub b_access: Array<MemoryReadCols<T>, <Bls12381BaseField as FieldParameters>::NB_LIMBS>,

    pub(crate) slope_denominator: QuadFieldOpCols<T, P>,
    pub(crate) slope_numerator: QuadFieldOpCols<T, P>,
    pub(crate) slope: QuadFieldOpCols<T, P>,
    pub(crate) slope_squared: QuadFieldOpCols<T, P>,
    pub(crate) p_x_plus_q_x: QuadFieldOpCols<T, P>,
    pub(crate) x3_ins: QuadFieldOpCols<T, P>,
    pub(crate) p_x_minus_x: QuadFieldOpCols<T, P>,
    pub(crate) y3_ins: QuadFieldOpCols<T, P>,
    pub(crate) slope_times_p_x_minus_x: QuadFieldOpCols<T, P>,
}

impl<T: PrimeField32> BaseAir<T> for Bls12381G2AffineAddChip {
    fn width(&self) -> usize {
        size_of::<Bls12381G2AffineAddCols<u8, Bls12381BaseField>>()
    }
}

impl<'a> WithEvents<'a> for Bls12381G2AffineAddChip {
    type InputEvents = &'a [Bls12381G2AffineAddEvent];
    type OutputEvents = &'a [ByteLookupEvent];
}

impl<F: PrimeField32> MachineAir<F> for Bls12381G2AffineAddChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "G2AffineAdd".to_string()
    }

    fn generate_trace<EL: EventLens<Self>, OL: EventMutLens<Self>>(
        &self,
        input: &EL,
        output: &mut OL,
    ) -> RowMajorMatrix<F> {
        let mut rows = vec![];

        let mut new_byte_lookup_events = Vec::new();

        let width = <Bls12381G2AffineAddChip as BaseAir<F>>::width(self);
        for event in input.events() {
            let mut row = vec![F::zero(); width];
            let cols: &mut Bls12381G2AffineAddCols<F, Bls12381BaseField> =
                row.as_mut_slice().borrow_mut();

            // SP1 / WP1 stuff
            cols.clk = F::from_canonical_u32(event.clk);
            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);

            // Data
            cols.a_ptr = F::from_canonical_u32(event.a_ptr);
            cols.b_ptr = F::from_canonical_u32(event.b_ptr);

            let a_x = AffinePoint::<Bls12381BaseField>::from_words_le(&event.a_x);
            let a_y = AffinePoint::<Bls12381BaseField>::from_words_le(&event.a_y);
            let b_x = AffinePoint::<Bls12381BaseField>::from_words_le(&event.b_x);
            let b_y = AffinePoint::<Bls12381BaseField>::from_words_le(&event.b_y);

            let (a_x_c0, a_x_c1) = (a_x.x, a_x.y);
            let (a_y_c0, a_y_c1) = (a_y.x, a_y.y);
            let (b_x_c0, b_x_c1) = (b_x.x, b_x.y);
            let (b_y_c0, b_y_c1) = (b_y.x, b_y.y);

            for i in 0..<Bls12381BaseField as FieldParameters>::NB_LIMBS::USIZE {
                cols.a_access[i].populate(event.a_memory_records[i], &mut new_byte_lookup_events);
            }

            for i in 0..<Bls12381BaseField as FieldParameters>::NB_LIMBS::USIZE {
                cols.b_access[i].populate(event.b_memory_records[i], &mut new_byte_lookup_events);
            }

            Self::populate_cols(
                &mut new_byte_lookup_events,
                event.shard,
                cols,
                &[a_x_c0, a_x_c1],
                &[a_y_c0, a_y_c1],
                &[b_x_c0, b_x_c1],
                &[b_y_c0, b_y_c1],
            );

            rows.push(row);
        }

        output.add_events(&new_byte_lookup_events);

        pad_vec_rows(&mut rows, || {
            let mut row = vec![F::zero(); width];
            let cols: &mut Bls12381G2AffineAddCols<F, Bls12381BaseField> =
                row.as_mut_slice().borrow_mut();

            cols.clk = F::zero();
            cols.is_real = F::zero();
            cols.shard = F::zero();

            let zero = BigUint::zero();
            Self::populate_cols(
                &mut vec![],
                0,
                cols,
                &[zero.clone(), zero.clone()],
                &[zero.clone(), zero.clone()],
                &[zero.clone(), zero.clone()],
                &[zero.clone(), zero.clone()],
            );
            row
        });

        RowMajorMatrix::<F>::new(rows.into_iter().flatten().collect::<Vec<_>>(), width)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.bls12381_g2_add_events.is_empty()
    }
}

impl<AB> Air<AB> for Bls12381G2AffineAddChip
where
    AB: MemoryAirBuilder,
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Bls12381G2AffineAddCols<AB::Var, Bls12381BaseField> = (*local).borrow();

        let p_x_c0: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> =
            limbs_from_prev_access(&local.a_access[0..12]);
        let p_x_c1: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> =
            limbs_from_prev_access(&local.a_access[12..24]);
        let p_y_c0: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> =
            limbs_from_prev_access(&local.a_access[24..36]);
        let p_y_c1: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> =
            limbs_from_prev_access(&local.a_access[36..48]);

        let q_x_c0: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> =
            limbs_from_access(&local.b_access[0..12]);
        let q_x_c1: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> =
            limbs_from_access(&local.b_access[12..24]);
        let q_y_c0: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> =
            limbs_from_access(&local.b_access[24..36]);
        let q_y_c1: Limbs<_, <Bls12381BaseField as FieldParameters>::NB_LIMBS> =
            limbs_from_access(&local.b_access[36..48]);

        let slope = {
            local.slope_numerator.eval(
                builder,
                &[q_y_c0, q_y_c1],
                &[p_y_c0, p_y_c1],
                QuadFieldOperation::Sub,
                local.shard,
                local.is_real,
            );

            local.slope_denominator.eval(
                builder,
                &[q_x_c0, q_x_c1],
                &[p_x_c0, p_x_c1],
                QuadFieldOperation::Sub,
                local.shard,
                local.is_real,
            );

            local.slope.eval(
                builder,
                &local.slope_numerator.result,
                &local.slope_denominator.result,
                QuadFieldOperation::Div,
                local.shard,
                local.is_real,
            );

            local.slope.result
        };

        let x = {
            local.slope_squared.eval(
                builder,
                &slope,
                &slope,
                QuadFieldOperation::Mul,
                local.shard,
                local.is_real,
            );

            local.p_x_plus_q_x.eval(
                builder,
                &[p_x_c0, p_x_c1],
                &[q_x_c0, q_x_c1],
                QuadFieldOperation::Add,
                local.shard,
                local.is_real,
            );

            local.x3_ins.eval(
                builder,
                &local.slope_squared.result,
                &local.p_x_plus_q_x.result,
                QuadFieldOperation::Sub,
                local.shard,
                local.is_real,
            );

            local.x3_ins.result
        };

        {
            local.p_x_minus_x.eval(
                builder,
                &[p_x_c0, p_x_c1],
                &x,
                QuadFieldOperation::Sub,
                local.shard,
                local.is_real,
            );

            local.slope_times_p_x_minus_x.eval(
                builder,
                &slope,
                &local.p_x_minus_x.result,
                QuadFieldOperation::Mul,
                local.shard,
                local.is_real,
            );

            local.y3_ins.eval(
                builder,
                &local.slope_times_p_x_minus_x.result,
                &[p_y_c0, p_y_c1],
                QuadFieldOperation::Sub,
                local.shard,
                local.is_real,
            );
        }

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]. This is to
        // ensure that p_access is updated with the new value.
        let x3_ins_x = &local.x3_ins.result[0];
        let x3_ins_y = &local.x3_ins.result[1];
        let y3_ins_x = &local.y3_ins.result[0];
        let y3_ins_y = &local.y3_ins.result[1];
        for i in 0..48 {
            builder
                .when(local.is_real)
                .assert_eq(x3_ins_x[i], local.a_access[i / 4].value()[i % 4]);
            builder
                .when(local.is_real)
                .assert_eq(x3_ins_y[i], local.a_access[12 + i / 4].value()[i % 4]);
            builder
                .when(local.is_real)
                .assert_eq(y3_ins_x[i], local.a_access[24 + i / 4].value()[i % 4]);
            builder
                .when(local.is_real)
                .assert_eq(y3_ins_y[i], local.a_access[36 + i / 4].value()[i % 4]);
        }

        // Memory constraints
        for i in 0..local.a_access.len() {
            builder.eval_memory_access(
                local.shard,
                local.clk + AB::F::from_canonical_u32(1), // We eval 'a' pointer access at clk+1 since 'a', 'b' could be the same
                local.a_ptr.into() + AB::F::from_canonical_u32((i as u32) * 4),
                &local.a_access[i],
                local.is_real,
            );
        }

        for i in 0..local.b_access.len() {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.b_ptr.into() + AB::F::from_canonical_u32((i as u32) * 4),
                &local.b_access[i],
                local.is_real,
            );
        }

        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::BLS12381_G2_ADD.syscall_id()),
            local.a_ptr,
            local.b_ptr,
            local.is_real,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::{Instruction, Opcode, SyscallCode};
    use crate::utils::ec::weierstrass::bls12_381::fp_to_biguint;
    use crate::utils::tests::BLS12381_G2_ADD_ELF;
    use crate::utils::{run_test, run_test_with_memory_inspection, setup_logger};
    use crate::Program;
    use bls12_381::G2Projective;
    use elliptic_curve::{group::Curve, Group};
    use num::{BigUint, Num};
    use rand::rngs::OsRng;

    fn biguint_str_to_words(input: &str, radix: u32) -> Vec<u32> {
        let output = BigUint::from_str_radix(input, radix).unwrap();
        biguint_to_words(&output)
    }

    fn biguint_to_words(input: &BigUint) -> Vec<u32> {
        let mut words = input.to_u32_digits();
        words.resize(12, 0);
        words
    }

    fn risc_v_program(a_ptr: u32, b_ptr: u32, a_words: Vec<u32>, b_words: Vec<u32>) -> Program {
        let mut instructions = vec![];
        for (index, word) in a_words.into_iter().enumerate() {
            instructions.push(Instruction::new(Opcode::ADD, 29, 0, word, false, true));
            instructions.push(Instruction::new(
                Opcode::ADD,
                30,
                0,
                a_ptr + (index * 4) as u32,
                false,
                true,
            ));
            instructions.push(Instruction::new(Opcode::SW, 29, 30, 0, false, true));
        }

        for (index, word) in b_words.into_iter().enumerate() {
            instructions.push(Instruction::new(Opcode::ADD, 29, 0, word, false, true));
            instructions.push(Instruction::new(
                Opcode::ADD,
                30,
                0,
                b_ptr + (index * 4) as u32,
                false,
                true,
            ));
            instructions.push(Instruction::new(Opcode::SW, 29, 30, 0, false, true));
        }

        instructions.push(Instruction::new(
            Opcode::ADD,
            5,
            0,
            SyscallCode::BLS12381_G2_ADD as u32,
            false,
            true,
        ));
        instructions.push(Instruction::new(Opcode::ADD, 10, 0, a_ptr, false, true));
        instructions.push(Instruction::new(Opcode::ADD, 11, 0, b_ptr, false, true));
        instructions.push(Instruction::new(Opcode::ECALL, 5, 10, 11, false, false));
        Program::new(instructions, 0, 0)
    }

    fn execute_risc_v_test(a_words: Vec<u32>, b_words: Vec<u32>, expected: &[BigUint]) {
        let a_ptr = 10000000u32;
        let b_ptr = 20000000u32;

        setup_logger();
        let program = risc_v_program(a_ptr, b_ptr, a_words, b_words);
        let (_, memory) = run_test_with_memory_inspection(program);
        let mut result = vec![];
        // Fp / BigUint is encoded as a 12 u32 words. G2Affine point has 4 Fp elements, so we read 4 * 12 words from the memory
        for i in 0..48 {
            #[allow(clippy::clone_on_copy)]
            result.push(memory.get(&(a_ptr + i * 4)).unwrap().clone().value);
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

    #[test]
    fn test_bls12381_g2_affine_add_precompile() {
        // input data
        let a_x_c0 = biguint_str_to_words("3017839990326613039145041105403203768289907560485999954764669466782738776913278597336115197412326608157502898901494", 10);
        let a_x_c1 = biguint_str_to_words("1968364904179875953612227826050294324304687258024434156939687758255052288526966247408321096642287030833236074834637", 10);
        let a_y_c0 = biguint_str_to_words("1112963802227266471936425299599962264551592268216698728003246008956141517020182272707792452981388955804771234793026", 10);
        let a_y_c1 = biguint_str_to_words("3601956566756065634979731486354880834166415754665429377259877200484386122313208466384188001260145428371483966256158", 10);

        let b_x_c0 = biguint_str_to_words("3995345726713524343478694139317244904221986402748125746531220355264073737425831917431067307136350406235257521914720", 10);
        let b_x_c1 = biguint_str_to_words("2371713999659141329582895752583386038540725886998376058382441223953471437659156083018472482942487601301212281350719", 10);
        let b_y_c0 = biguint_str_to_words("1657736472727646860487013511699214065739000373955759070260564759907290637218762525626953919644264064293125883245513", 10);
        let b_y_c1 = biguint_str_to_words("669840849348882079501065523381492957342969119764450012349355587264902894823664213163993856854342667498557678470765", 10);

        let expected_x_c0 = BigUint::from_str_radix("2217453026271814368440203317808683516910566559070156396650784209828414583877914335476042658864001902388991070392394", 10).unwrap();
        let expected_x_c1 = BigUint::from_str_radix("3735586588151792717344356536686990055696764520142017086471655175341858001563444141499357084899636851157467845644056", 10).unwrap();
        let expected_y_c0 = BigUint::from_str_radix("2258336512095698119772266602759054637810622833780250581163613657159437682816906766646529574247756287023363655074151", 10).unwrap();
        let expected_y_c1 = BigUint::from_str_radix("941210928186334692595956191674128264366290431929708551370700737070865409698010117261045198014833047669542376970151", 10).unwrap();

        let a_words = [a_x_c0, a_x_c1, a_y_c0, a_y_c1].concat();
        let b_words = [b_x_c0, b_x_c1, b_y_c0, b_y_c1].concat();

        execute_risc_v_test(
            a_words,
            b_words,
            vec![expected_x_c0, expected_x_c1, expected_y_c0, expected_y_c1].as_slice(),
        );
    }

    #[test]
    fn test_bls12381_g2_affine_add_precompile_flaky_input() {
        // input data
        let a_x_c0 = biguint_str_to_words("940678610412633391924225779762290732605526547639243864351304234419401586596082223466014582312599779726285805697475", 10);
        let a_x_c1 = biguint_str_to_words("3970533371664127278374320743636293284643681224131866516566888981399830088697294165563145438098385314712450903750583", 10);
        let a_y_c0 = biguint_str_to_words("2871772792170856534319532679530995220771426110922375294987607996910186965076421817067724466403137338049516993640951", 10);
        let a_y_c1 = biguint_str_to_words("0053793603554162309816446837984978293593915145569675366398752348829921241608048564007856072778551661809103745377287", 10);

        let b_x_c0 = biguint_str_to_words("1331464510641249323839094619361852670403027671905433475300506442976146288503285736268135124866206040312808602176295", 10);
        let b_x_c1 = biguint_str_to_words("3027642434952722503753323015041364214878978079475767163845055204071467562888064074234522216329340479780081790725137", 10);
        let b_y_c0 = biguint_str_to_words("200696228981224618855716420820649730377778982335265086880186071238717972653859952113546787814946905099483255668391", 10);
        let b_y_c1 = biguint_str_to_words("2577651373384445415166436815683162788302596986034982084134306770915573381249081261772662199090886949623499138384248", 10);

        let expected_x_c0 = BigUint::from_str_radix("2860343709557806964027158749871320254572140155920054742718333850477275802846203645466077272289804508903032673035205", 10).unwrap();
        let expected_x_c1 = BigUint::from_str_radix("2104523116857637401022553203989683783163518619859130296649146989961080115867556546075155138043913256307617354725201", 10).unwrap();
        let expected_y_c0 = BigUint::from_str_radix("3285167425898843195224794751434504763710550311489867065524684573545527680992036398300984330533695019506363839092244", 10).unwrap();
        let expected_y_c1 = BigUint::from_str_radix("700752659476098625384975476746701395987863643330498795166428473984414216525778183396070281760298054977309932101839", 10).unwrap();

        let a_words = [a_x_c0, a_x_c1, a_y_c0, a_y_c1].concat();
        let b_words = [b_x_c0, b_x_c1, b_y_c0, b_y_c1].concat();

        execute_risc_v_test(
            a_words,
            b_words,
            vec![expected_x_c0, expected_x_c1, expected_y_c0, expected_y_c1].as_slice(),
        );
    }

    #[test]
    fn test_bls12381_g2_affine_add_precompile_randomized_input() {
        let mut rng = OsRng;
        let a = G2Projective::random(&mut rng);
        let b = G2Projective::random(&mut rng);

        let expected = (a + b).to_affine();
        let a_affine = a.to_affine();
        let b_affine = b.to_affine();

        let a_x_c0 = fp_to_biguint(&a_affine.x.c0);
        let a_x_c1 = fp_to_biguint(&a_affine.x.c1);
        let a_y_c0 = fp_to_biguint(&a_affine.y.c0);
        let a_y_c1 = fp_to_biguint(&a_affine.y.c1);
        let b_x_c0 = fp_to_biguint(&b_affine.x.c0);
        let b_x_c1 = fp_to_biguint(&b_affine.x.c1);
        let b_y_c0 = fp_to_biguint(&b_affine.y.c0);
        let b_y_c1 = fp_to_biguint(&b_affine.y.c1);
        let expected_x_c0 = fp_to_biguint(&expected.x.c0);
        let expected_x_c1 = fp_to_biguint(&expected.x.c1);
        let expected_y_c0 = fp_to_biguint(&expected.y.c0);
        let expected_y_c1 = fp_to_biguint(&expected.y.c1);

        let a_words = [
            biguint_to_words(&a_x_c0),
            biguint_to_words(&a_x_c1),
            biguint_to_words(&a_y_c0),
            biguint_to_words(&a_y_c1),
        ]
        .concat();

        let b_words = [
            biguint_to_words(&b_x_c0),
            biguint_to_words(&b_x_c1),
            biguint_to_words(&b_y_c0),
            biguint_to_words(&b_y_c1),
        ]
        .concat();

        execute_risc_v_test(
            a_words,
            b_words,
            vec![expected_x_c0, expected_x_c1, expected_y_c0, expected_y_c1].as_slice(),
        );
    }

    #[test]
    fn test_bls12381_g2_addition_precompile_elf() {
        setup_logger();
        let program = Program::from(BLS12381_G2_ADD_ELF);
        run_test(program).unwrap();
    }
}
