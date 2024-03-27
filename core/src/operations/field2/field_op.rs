use crate::air::Polynomial;
use crate::air::SP1AirBuilder;
use crate::operations::field::params::LimbWidth;
use crate::operations::field::params::Limbs;
use crate::operations::field::params::DEFAULT_NUM_LIMBS_T;
use crate::operations::field::params::WITNESS_LIMBS;
use crate::operations::field::util::{
    compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs,
};
use crate::operations::field::util_air::eval_field_operation;
use crate::utils::ec::field::FieldParameters;
use hybrid_array::{typenum::Unsigned, Array};
use num::{BigInt, BigUint, Zero};
use p3_air::AirBuilder;
use p3_field::PrimeField32;
use std::fmt::Debug;
use wp1_derive::AlignedBorrow;

/// Quadratic field operation
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum Field2Operation {
    Add,
    Mul,
    Sub,
    //Div, // We don't constrain that the divisor is non-zero.
}

/// A set of columns to compute `FieldOperation(a, b)` where a, b are field elements.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Field2OpCols<T, U: LimbWidth = DEFAULT_NUM_LIMBS_T> {
    /// The result of `a op b`, where a, b are field elements
    pub result: [Limbs<T, U>; 2],
    pub(crate) carry: [Limbs<T, U>; 2],
    pub(crate) witness_low: [Array<T, WITNESS_LIMBS<U>>; 2],
    pub(crate) witness_high: [Array<T, WITNESS_LIMBS<U>>; 2],
    modulus: Limbs<T, U>, // FIXME: shouldn't exist here ideally, but the generic bounds in eval annoyingly don't include PrimeField32
}

impl<F: PrimeField32, U: LimbWidth> Field2OpCols<F, U> {
    pub fn populate<P: FieldParameters<NB_LIMBS = U>>(
        &mut self,
        a: &[BigUint; 2],
        b: &[BigUint; 2],
        op: Field2Operation,
    ) -> [BigUint; 2] {
        // eprintln!("a: {:?} b: {:?}, op: {:?}", a, b, op);
        /*if b[0] == BigUint::zero() && b[1] == BigUint::zero() && op == Field2Operation::Div {
            // Division by 0 is allowed only when dividing 0 so that padded rows can be all 0.
            assert_eq!(
                a[0],
                BigUint::zero(),
                "division by zero is allowed only when dividing zero"
            );
            assert_eq!(
                a[1],
                BigUint::zero(),
                "division by zero is allowed only when dividing zero"
            );
        }*/

        let modulus = P::modulus();

        // If doing the subtraction operation, a - b = result, equivalent to a = result + b.
        if op == Field2Operation::Sub {
            let result = [
                (&modulus + &a[0] - &b[0]) % &modulus,
                (&modulus + &a[1] - &b[1]) % &modulus,
            ];
            // We populate the carry, witness_low, witness_high as if we were doing an addition with result + b.
            // But we populate `result` with the actual result of the subtraction because those columns are expected
            // to contain the result by the user.
            // Note that this reversal means we have to flip result, a correspondingly in
            // the `eval` function.
            self.populate::<P>(&result, b, Field2Operation::Add);
            self.result = [
                P::to_limbs_field::<F>(&result[0]),
                P::to_limbs_field::<F>(&result[1]),
            ];
            return result;
        }

        /*
        // a / b = result is equivalent to a = result * b.
        if op == Field2Operation::Div {
            // As modulus is prime, we can use Fermat's little theorem to compute the
            // inverse.
            let result = (a * b.modpow(&(&modulus - 2u32), &modulus)) % modulus;

            // We populate the carry, witness_low, witness_high as if we were doing a multiplication
            // with result * b. But we populate `result` with the actual result of the
            // multiplication because those columns are expected to contain the result by the user.
            // Note that this reversal means we have to flip result, a correspondingly in the `eval`
            // function.
            self.populate::<P>(&result, b, FieldOperation::Mul);
            self.result = P::to_limbs_field::<F>(&result);
            return result;
        }
        */

        let p_a: [Polynomial<F>; 2] = [
            P::to_limbs_field::<F>(&a[0]).into(),
            P::to_limbs_field::<F>(&a[1]).into(),
        ];
        let p_b: [Polynomial<F>; 2] = [
            P::to_limbs_field::<F>(&b[0]).into(),
            P::to_limbs_field::<F>(&b[1]).into(),
        ];

        // Compute field addition in the integers.
        let modulus = &P::modulus();
        // let mul_res = {
        //     let T0 = &a[0] * &b[0];
        //     let T1 = &a[1] * &b[1];
        //     let t0 = &a[0] + &a[1];
        //     let t1 = &b[0] + &b[1];
        //     let T2 = &t0 * &t1;
        //     let T3 = &T0 + &T1;
        //     let T2 = &T2 - &T3;
        //     let T0 = modulus * modulus + &T0 - &T1;
        //     (T2, T0)
        //     dbg!(modulus);
        //     dbg!(&T0);
        //     dbg!(&T1);
        //     dbg!(modulus * modulus + &T0 - &T1);
        //     dbg!(&t0);
        //     dbg!(&t1);
        //     dbg!(&T2);
        //     dbg!(&T3);
        //     panic!();
        // };
        // eprintln!("a: {:?}", a);
        // eprintln!("b: {:?}", b);
        // eprintln!("mod: {:?}", modulus);
        let tmp_mulbigsub = {
            let t1 = &a[0] * &b[0];
            let t2 = &a[1] * &b[1];
            // eprintln!("t1: {:?}", t1);
            // eprintln!("t2: {:?}", t2);
            // eprintln!("t1 mod: {:?}", &t1 % modulus);
            // eprintln!("t2 mod: {:?}", &t2 % modulus);
            // eprintln!("res: {:?}", (modulus + (&t1 % modulus) - (&t2 % modulus)));
            // eprintln!("res2: {:?}", (modulus + (&t1 % modulus) - (&t2 % modulus)) % modulus);
            modulus*modulus + t1 - t2
            // if t1 >= t2 {
            //     (t1 - t2, false)
            // } else {
            //     (modulus + t1 - t2, true)
            //     // let d1 = &t1 / modulus;
            //     // let d2 = &t2 / modulus;
            //     // dbg!(&t1);
            //     // dbg!(&t2);
            //     // dbg!(&d1);
            //     // dbg!(&d2);
            //     // dbg!(&d2 - &d1);
            //     // dbg!((&d2 - &d1)*modulus + &t1);
            //     // ((d2 - d1 + BigUint::from(1u32))*modulus + t1 - t2, true)
            // }
        };
        let (result, carry) = match op {
            Field2Operation::Add => ([(&a[0] + &b[0]) % modulus,
                                      (&a[1] + &b[1]) % modulus],
                                     [(&a[0] + &b[0] - (&a[0] + &b[0]) % modulus) / modulus,
                                      (&a[1] + &b[1] - (&a[1] + &b[1]) % modulus) / modulus]),
            Field2Operation::Mul => ([&tmp_mulbigsub % modulus,
                                      (&a[0]*&b[1] + &a[1]*&b[0]) % modulus],
                                     [(&tmp_mulbigsub - &tmp_mulbigsub % modulus) / modulus,
                                      (&a[0]*&b[1] + &a[1]*&b[0] - (&a[0]*&b[1] + &a[1]*&b[0]) % modulus) / modulus]),
            // Field2Operation::Mul => ([(&a[0]*&b[0] - &a[1]*&b[1]) % modulus,
            //                           (&a[0]*&b[1] + &a[1]*&b[0]) % modulus],
            //                          [(&a[0]*&b[0] - &a[1]*&b[1] - (&a[0]*&b[0] - &a[1]*&b[1]) % modulus) / modulus,
            //                           (&a[0]*&b[1] + &a[1]*&b[0] - (&a[0]*&b[1] + &a[1]*&b[0]) % modulus) / modulus]),
            Field2Operation::Sub /*| FieldOperation::Div*/ => unreachable!(),
        };
        // eprintln!("result: {:?}", result);
        // eprintln!("carry: {:?}", carry);
        debug_assert!(&result[0] < modulus);
        debug_assert!(&result[1] < modulus);
        if op == Field2Operation::Mul {
            debug_assert!(carry[0] < BigUint::from(2u32) * modulus);
            debug_assert!(carry[1] < BigUint::from(2u32) * modulus);
        } else {
            debug_assert!(&carry[0] < modulus);
            debug_assert!(&carry[1] < modulus);
        }
        match op {
            Field2Operation::Add => {
                debug_assert_eq!(&carry[0] * modulus, &a[0] + &b[0] - &result[0]);
                debug_assert_eq!(&carry[1] * modulus, &a[1] + &b[1] - &result[1]);
            },
            Field2Operation::Mul => {
                debug_assert_eq!(&carry[0] * modulus, &tmp_mulbigsub - &result[0]);
                debug_assert_eq!(&carry[1] * modulus, (&a[0]*&b[1] + &a[1]*&b[0]) - &result[1]);
            },
            Field2Operation::Sub /*| FieldOperation::Div*/ => unreachable!(),
        }

        // Make little endian polynomial limbs.
        let p_modulus: Polynomial<F> = P::to_limbs_field::<F>(modulus).into();
        let p_result: [Polynomial<F>; 2] = [
            P::to_limbs_field::<F>(&result[0]).into(),
            P::to_limbs_field::<F>(&result[1]).into(),
        ];
        // eprintln!("{:?}", carry);
        let p_carry: [Polynomial<F>; 2] = [
            P::to_limbs_field::<F>(&carry[0]).into(),
            P::to_limbs_field::<F>(&carry[1]).into(),
        ];
        // let eval_p = |x: &Polynomial<F>| -> F {
        //     x
        //         .coefficients()
        //         .iter()
        //         .enumerate()
        //         .map(|(i, x)| {
        //             crate::operations::field::util::biguint_to_field::<F>(&BigUint::from(2u32).pow((P::NB_BITS_PER_LIMB * i) as u32)) * *x
        //         })
        //         .sum::<F>()
        // };

        // eprintln!("order: {:?}", F::order());
        // eprintln!("p_a: {:?}", p_a[0]);
        // eprintln!("a: {:?}", a[0]);
        // eprintln!("a mod: {:?}", &a[0] % F::order());
        // eprintln!("eval_p_a: {:?}", eval_p(&p_a[0]));

        // eprintln!("p_b: {:?}", p_b);
        // eprintln!("tmp: {:?}", tmp_mulbigsub);

        // Compute the vanishing polynomial.
        let p_op = match op {
            Field2Operation::Add => [&p_a[0] + &p_b[0], &p_a[1] + &p_b[1]],
            //Field2Operation::Mul => [if tmp { p_modulus.clone() + &p_a[0]*&p_b[0] - &p_a[1]*&p_b[1] } else { &p_a[0]*&p_b[0] - &p_a[1]*&p_b[1] },
            Field2Operation::Mul => [&p_modulus*&p_modulus + &p_a[0]*&p_b[0] - &p_a[1]*&p_b[1],
                                     &p_a[0]*&p_b[1] + &p_a[1]*&p_b[0]],
            Field2Operation::Sub /*| FieldOperation::Div*/ => unreachable!(),
        };
        // eprintln!("p_op: {:?}", p_op);
        let p_vanishing: [Polynomial<F>; 2] = [
            &p_op[0] - &p_result[0] - &p_carry[0] * &p_modulus,
            &p_op[1] - &p_result[1] - &p_carry[1] * &p_modulus,
        ];
        // eprintln!("p_vanishing: {:?}", p_vanishing);
        debug_assert_eq!(p_vanishing[0].degree(), WITNESS_LIMBS::<U>::USIZE);
        debug_assert_eq!(p_vanishing[1].degree(), WITNESS_LIMBS::<U>::USIZE);

        let p_witness = [
            compute_root_quotient_and_shift(
                &p_vanishing[0],
                P::WITNESS_OFFSET,
                P::NB_BITS_PER_LIMB as u32,
            ),
            compute_root_quotient_and_shift(
                &p_vanishing[1],
                P::WITNESS_OFFSET,
                P::NB_BITS_PER_LIMB as u32,
            ),
        ];
        let (p_witness_low_0, p_witness_high_0) = split_u16_limbs_to_u8_limbs(&p_witness[0]);
        let (p_witness_low_1, p_witness_high_1) = split_u16_limbs_to_u8_limbs(&p_witness[1]);

        self.result = [p_result[0].clone().into(), p_result[1].clone().into()];
        self.carry = [p_carry[0].clone().into(), p_carry[1].clone().into()];
        self.witness_low = [
            (&p_witness_low_0[..]).try_into().unwrap(),
            (&p_witness_low_1[..]).try_into().unwrap(),
        ];
        self.witness_high = [
            (&p_witness_high_0[..]).try_into().unwrap(),
            (&p_witness_high_1[..]).try_into().unwrap(),
        ];
        self.modulus = P::to_limbs_field::<F>(modulus);

        result
    }
}

impl<V: Copy, U: LimbWidth> Field2OpCols<V, U> {
    pub fn eval<
        AB: SP1AirBuilder<Var = V>,
        P: FieldParameters<NB_LIMBS = U>,
        A: Into<Polynomial<AB::Expr>> + Clone,
        B: Into<Polynomial<AB::Expr>> + Clone,
    >(
        &self,
        builder: &mut AB,
        a: &[A; 2],
        b: &[B; 2],
        op: Field2Operation,
    ) where
        V: Into<AB::Expr>,
    {
        let p_a_param: [Polynomial<AB::Expr>; 2] = [(a[0]).clone().into(), (a[1]).clone().into()];
        let p_b: [Polynomial<AB::Expr>; 2] = [(b[0]).clone().into(), (b[1]).clone().into()];

        let (p_a, p_result): ([Polynomial<_>; 2], [Polynomial<_>; 2]) = match op {
            Field2Operation::Add | Field2Operation::Mul => (p_a_param, [self.result[0].clone().into(), self.result[1].clone().into()]),
            Field2Operation::Sub /*| FieldOperation::Div*/ => ([self.result[0].clone().into(), self.result[1].clone().into()], p_a_param),
        };
        let p_carry: [Polynomial<<AB as AirBuilder>::Expr>; 2] =
            [self.carry[0].clone().into(), self.carry[1].clone().into()];
        // let p_op = match op {
        //     Field2Operation::Add | Field2Operation::Sub => p_a + p_b,
        //     Field2Operation::Mul /*| FieldOperation::Div*/ => p_a * p_b,
        // };
        let p_modulus: Polynomial<AB::Expr> = self.modulus.clone().into();
        let p_op = match op {
            Field2Operation::Add | Field2Operation::Sub => [&p_a[0] + &p_b[0], &p_a[1] + &p_b[1]],
            Field2Operation::Mul => [
                &p_modulus * &p_modulus + &p_a[0] * &p_b[0] - &p_a[1] * &p_b[1],
                &p_a[0] * &p_b[1] + &p_a[1] * &p_b[0],
            ],
        };
        let p_op_minus_result: [Polynomial<AB::Expr>; 2] = [
            p_op[0].clone() - p_result[0].clone(),
            p_op[1].clone() - p_result[1].clone(),
        ];
        let p_limbs = P::modulus_field_iter::<AB::F>()
            .map(AB::Expr::from)
            .collect();
        let p_vanishing = [
            p_op_minus_result[0].clone() - &(&p_carry[0] * &p_limbs),
            p_op_minus_result[1].clone() - &(&p_carry[1] * &p_limbs),
        ];
        let p_witness_low = [
            self.witness_low[0].iter().into(),
            self.witness_low[1].iter().into(),
        ];
        let p_witness_high = [
            self.witness_high[0].iter().into(),
            self.witness_high[1].iter().into(),
        ];
        eval_field_operation::<AB, P>(
            builder,
            &p_vanishing[0],
            &p_witness_low[0],
            &p_witness_high[0],
        );
        eval_field_operation::<AB, P>(
            builder,
            &p_vanishing[1],
            &p_witness_low[1],
            &p_witness_high[1],
        );
    }
}

#[cfg(test)]
mod tests {
    use num::BigUint;
    use p3_air::BaseAir;
    use p3_field::{Field, PrimeField32};

    use super::{Field2OpCols, Field2Operation};
    use crate::operations::field::params::Limbs;

    use crate::air::MachineAir;
    use crate::operations::field::params::LimbWidth;
    use crate::stark::StarkGenericConfig;
    use crate::utils::ec::edwards::ed25519::Ed25519BaseField;
    use crate::utils::ec::field::FieldParameters;
    use crate::utils::ec::weierstrass::bls12381::Bls12381BaseField;
    use crate::utils::ec::weierstrass::secp256k1::Secp256k1BaseField;
    use crate::utils::{pad_to_power_of_two_nongeneric, BabyBearPoseidon2};
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use crate::{air::SP1AirBuilder, runtime::ExecutionRecord};
    use core::borrow::{Borrow, BorrowMut};
    use core::mem::size_of;
    use num::bigint::RandBigInt;
    use p3_air::Air;
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::MatrixRowSlices;
    use rand::thread_rng;
    use wp1_derive::AlignedBorrow;

    #[derive(AlignedBorrow, Debug, Clone)]
    pub struct TestCols<T, U: LimbWidth> {
        pub a: [Limbs<T, U>; 2],
        pub b: [Limbs<T, U>; 2],
        pub a_op_b: Field2OpCols<T, U>,
    }

    struct Field2OpChip<P: FieldParameters> {
        pub(crate) operation: Field2Operation,
        pub(crate) _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> Field2OpChip<P> {
        pub(crate) fn new(operation: Field2Operation) -> Self {
            Self {
                operation,
                _phantom: std::marker::PhantomData,
            }
        }
    }

    impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for Field2OpChip<P> {
        type Record = ExecutionRecord;

        fn name(&self) -> String {
            format!("Field2Op{:?}", self.operation)
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            let mut rng = thread_rng();
            let num_rows = 1 << 8;
            let mut operands: Vec<([BigUint; 2], [BigUint; 2])> = (0..num_rows - 5)
                .map(|_| {
                    let a = [
                        rng.gen_biguint(P::nb_bits() as u64) % &P::modulus(),
                        rng.gen_biguint(P::nb_bits() as u64) % &P::modulus(),
                    ];
                    let b = [
                        rng.gen_biguint(P::nb_bits() as u64) % &P::modulus(),
                        rng.gen_biguint(P::nb_bits() as u64) % &P::modulus(),
                    ];
                    (a, b)
                })
                .collect();

            // Hardcoded edge cases. We purposely include 0 / 0. While mathematically, that is not
            // allowed, we allow it in our implementation so padded rows can be all 0.
            operands.extend(vec![
                (
                    [BigUint::from(0u32), BigUint::from(0u32)],
                    [BigUint::from(0u32), BigUint::from(0u32)],
                ),
                (
                    [BigUint::from(0u32), BigUint::from(0u32)],
                    [BigUint::from(1u32), BigUint::from(0u32)],
                ),
                (
                    [BigUint::from(1u32), BigUint::from(1u32)],
                    [BigUint::from(2u32), BigUint::from(1u32)],
                ),
                (
                    [BigUint::from(4u32), BigUint::from(4u32)],
                    [BigUint::from(5u32), BigUint::from(5u32)],
                ),
                (
                    [BigUint::from(10u32), BigUint::from(19u32)],
                    [BigUint::from(19u32), BigUint::from(10u32)],
                ),
            ]);

            let num_test_cols = <Field2OpChip<P> as BaseAir<F>>::width(self);

            let rows = operands
                .iter()
                .map(|(a, b)| {
                    let mut row = vec![F::zero(); num_test_cols];
                    let cols: &mut TestCols<F, P::NB_LIMBS> = row.as_mut_slice().borrow_mut();
                    cols.a = [P::to_limbs_field::<F>(&a[0]), P::to_limbs_field::<F>(&a[1])];
                    cols.b = [P::to_limbs_field::<F>(&b[0]), P::to_limbs_field::<F>(&b[1])];
                    cols.a_op_b.populate::<P>(a, b, self.operation);
                    row
                })
                .collect::<Vec<_>>();
            // Convert the trace to a row major matrix.
            let mut trace = RowMajorMatrix::new(
                rows.into_iter().flatten().collect::<Vec<_>>(),
                num_test_cols,
            );

            // Pad the trace to a power of two.
            pad_to_power_of_two_nongeneric::<F>(num_test_cols, &mut trace.values);

            trace
        }

        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<F: Field, P: FieldParameters> BaseAir<F> for Field2OpChip<P> {
        fn width(&self) -> usize {
            size_of::<TestCols<u8, P::NB_LIMBS>>()
        }
    }

    impl<AB, P: FieldParameters> Air<AB> for Field2OpChip<P>
    where
        AB: SP1AirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local: &TestCols<AB::Var, P::NB_LIMBS> = main.row_slice(0).borrow();
            local
                .a_op_b
                .eval::<AB, P, _, _>(builder, &local.a, &local.b, self.operation);

            // A dummy constraint to keep the degree 3.
            builder.assert_zero(
                local.a[0][0] * local.b[0][0] * local.a[0][0]
                    - local.a[0][0] * local.b[0][0] * local.a[0][0],
            )
        }
    }

    fn generate_trace_for<F: FieldParameters>() {
        for op in [
            Field2Operation::Add,
            Field2Operation::Sub,
            Field2Operation::Mul,
        ]
        .iter()
        {
            println!("op: {:?}", op);
            let chip: Field2OpChip<F> = Field2OpChip::new(*op);
            let shard = ExecutionRecord::default();
            let _trace: RowMajorMatrix<BabyBear> =
                chip.generate_trace(&shard, &mut ExecutionRecord::default());
            // println!("{:?}", _trace.values)
        }
    }

    fn prove_babybear_for<F: FieldParameters>() {
        let config = BabyBearPoseidon2::new();

        for op in [
            Field2Operation::Add,
            Field2Operation::Sub,
            Field2Operation::Mul,
        ]
        .iter()
        {
            println!("op: {:?}", op);

            let mut challenger = config.challenger();

            let chip: Field2OpChip<F> = Field2OpChip::new(*op);
            let shard = ExecutionRecord::default();
            let trace: RowMajorMatrix<BabyBear> =
                chip.generate_trace(&shard, &mut ExecutionRecord::default());
            let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

            let mut challenger = config.challenger();
            verify(&config, &chip, &mut challenger, &proof).unwrap();
        }
    }

    #[test]
    fn generate_trace() {
        generate_trace_for::<Ed25519BaseField>();
        generate_trace_for::<Bls12381BaseField>();
        //generate_trace_for::<Secp256k1BaseField>();
    }

    #[test]
    fn prove_babybear() {
        prove_babybear_for::<Ed25519BaseField>();
        prove_babybear_for::<Bls12381BaseField>();
        //prove_babybear_for::<Secp256k1BaseField>();
    }
}
