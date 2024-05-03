use std::fmt::Debug;

use hybrid_array::{typenum::Unsigned, Array};
use num::{BigUint, Integer, Zero};
use p3_air::AirBuilder;
use p3_field::PrimeField32;
use wp1_derive::AlignedBorrow;

use super::params::{FieldParameters, Limbs, WITNESS_LIMBS};
use super::util::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs};
use super::util_air::eval_field_operation;
use crate::air::Polynomial;
use crate::air::SP1AirBuilder;
use crate::bytes::event::ByteRecord;

/// Airthmetic operation for emulating modular arithmetic.
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum FieldOperation {
    Add,
    Mul,
    Sub,
    Div,
}

/// A set of columns to compute an emulated modular arithmetic operation.
///
/// *Safety* The input operands (a, b) (not included in the operation columns) are assumed to be
/// elements within the range `[0, 2^{P::nb_bits()})`. the result is also assumed to be within the
/// same range. Let `M = P:modulus()`. The constraints of the function [`FieldOpCols::eval`] assert
/// that:
/// * When `op` is `FieldOperation::Add`, then `result = a + b mod M`.
/// * When `op` is `FieldOperation::Mul`, then `result = a * b mod M`.
/// * When `op` is `FieldOperation::Sub`, then `result = a - b mod M`.
/// * When `op` is `FieldOperation::Div`, then `result * b = a  mod M`.
///
/// **Warning**: The constraints do not check for division by zero. The caller is responsible for
/// ensuring that the division operation is valid.
#[derive(Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldOpCols<T, P: FieldParameters> {
    /// The result of `a op b`, where a, b are field elements
    pub result: Limbs<T, P::NB_LIMBS>,
    pub(crate) carry: Limbs<T, P::NB_LIMBS>,
    pub(crate) witness_low: Array<T, WITNESS_LIMBS<P::NB_LIMBS>>,
    pub(crate) witness_high: Array<T, WITNESS_LIMBS<P::NB_LIMBS>>,
}

impl<T: Debug, P: FieldParameters> Debug for FieldOpCols<T, P> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("FieldOpCols")
            .field("result", &self.result)
            .field("carry", &self.carry)
            .field("witness_low", &self.witness_low)
            .field("witness_high", &self.witness_high)
            .finish()
    }
}

impl<F: PrimeField32, P: FieldParameters> FieldOpCols<F, P> {
    pub fn populate_carry_and_witness(
        &mut self,
        a: &BigUint,
        b: &BigUint,
        op: FieldOperation,
    ) -> BigUint {
        let p_a: Polynomial<F> = P::to_limbs_field::<F>(a).into();
        let p_b: Polynomial<F> = P::to_limbs_field::<F>(b).into();

        // Compute field addition in the integers.
        let modulus = &P::modulus();
        let (result, carry) = match op {
            FieldOperation::Add => {
                let (q1, r1) = (a + b).div_rem(modulus);
                (r1, q1)
            }
            FieldOperation::Mul => {
                let (q1, r1) = (a * b).div_rem(modulus);
                (r1, q1)
            }
            FieldOperation::Sub | FieldOperation::Div => unreachable!(),
        };
        debug_assert!(&result < modulus);
        debug_assert!(&carry < modulus);
        match op {
            FieldOperation::Add => debug_assert_eq!(&carry * modulus, a + b - &result),
            FieldOperation::Mul => debug_assert_eq!(&carry * modulus, a * b - &result),
            FieldOperation::Sub | FieldOperation::Div => unreachable!(),
        }

        // Make little endian polynomial limbs.
        let p_modulus: Polynomial<F> = P::to_limbs_field::<F>(modulus).into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F>(&result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F>(&carry).into();

        // Compute the vanishing polynomial.
        let p_op = match op {
            FieldOperation::Add => &p_a + &p_b,
            FieldOperation::Mul => &p_a * &p_b,
            FieldOperation::Sub | FieldOperation::Div => unreachable!(),
        };
        let p_vanishing: Polynomial<F> = &p_op - &p_result - &p_carry * &p_modulus;
        debug_assert_eq!(p_vanishing.degree(), WITNESS_LIMBS::<P::NB_LIMBS>::USIZE);

        let p_witness = compute_root_quotient_and_shift(
            &p_vanishing,
            P::WITNESS_OFFSET,
            P::NB_BITS_PER_LIMB as u32,
        );
        let (p_witness_low, p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

        self.result = p_result.try_into().unwrap();
        self.carry = p_carry.try_into().unwrap();
        self.witness_low = (&p_witness_low[..]).try_into().unwrap();
        self.witness_high = (&p_witness_high[..]).try_into().unwrap();

        result
    }

    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        shard: u32,
        a: &BigUint,
        b: &BigUint,
        op: FieldOperation,
    ) -> BigUint {
        if b == &BigUint::zero() && op == FieldOperation::Div {
            // Division by 0 is allowed only when dividing 0 so that padded rows can be all 0.
            assert_eq!(
                *a,
                BigUint::zero(),
                "division by zero is allowed only when dividing zero"
            );
        }

        let modulus = P::modulus();

        let result = match op {
            // If doing the subtraction operation, a - b = result, equivalent to a = result + b.
            FieldOperation::Sub => {
                let result = (modulus.clone() + a - b) % &modulus;
                // We populate the carry, witness_low, witness_high as if we were doing an addition with result + b.
                // But we populate `result` with the actual result of the subtraction because those columns are expected
                // to contain the result by the user.
                // Note that this reversal means we have to flip result, a correspondingly in
                // the `eval` function.
                self.populate_carry_and_witness(&result, b, FieldOperation::Add);
                self.result = P::to_limbs_field::<F>(&result);
                result
            }
            // a / b = result is equivalent to a = result * b.
            FieldOperation::Div => {
                // As modulus is prime, we can use Fermat's little theorem to compute the
                // inverse.
                let result =
                    (a * b.modpow(&(modulus.clone() - 2u32), &modulus.clone())) % modulus.clone();

                // We populate the carry, witness_low, witness_high as if we were doing a multiplication
                // with result * b. But we populate `result` with the actual result of the
                // multiplication because those columns are expected to contain the result by the user.
                // Note that this reversal means we have to flip result, a correspondingly in the `eval`
                // function.
                self.populate_carry_and_witness(&result, b, FieldOperation::Mul);
                self.result = P::to_limbs_field::<F>(&result);
                result
            }
            _ => self.populate_carry_and_witness(a, b, op),
        };

        // Range checks
        record.add_u8_range_checks_field(shard, &self.result);
        record.add_u8_range_checks_field(shard, &self.carry);
        record.add_u8_range_checks_field(shard, &self.witness_low);
        record.add_u8_range_checks_field(shard, &self.witness_high);

        result
    }
}

impl<V: Copy, P: FieldParameters> FieldOpCols<V, P> {
    pub fn eval<
        AB: SP1AirBuilder<Var = V>,
        A: Into<Polynomial<AB::Expr>> + Clone,
        B: Into<Polynomial<AB::Expr>> + Clone,
        EShard: Into<AB::Expr> + Clone,
        ER: Into<AB::Expr> + Clone,
    >(
        &self,
        builder: &mut AB,
        a: &A,
        b: &B,
        op: FieldOperation,
        shard: EShard,
        is_real: ER,
    ) where
        V: Into<AB::Expr>,
    {
        let p_a_param: Polynomial<AB::Expr> = (*a).clone().into();
        let p_b: Polynomial<AB::Expr> = (*b).clone().into();

        let (p_a, p_result): (Polynomial<_>, Polynomial<_>) = match op {
            FieldOperation::Add | FieldOperation::Mul => (p_a_param, self.result.clone().into()),
            FieldOperation::Sub | FieldOperation::Div => (self.result.clone().into(), p_a_param),
        };
        let p_carry: Polynomial<<AB as AirBuilder>::Expr> = self.carry.clone().into();
        let p_op = match op {
            FieldOperation::Add | FieldOperation::Sub => p_a + p_b,
            FieldOperation::Mul | FieldOperation::Div => p_a * p_b,
        };
        let p_op_minus_result: Polynomial<AB::Expr> = p_op - &p_result;
        let p_limbs = Polynomial::from_iter(P::modulus_field_iter::<AB::F>().map(AB::Expr::from));
        let p_vanishing = p_op_minus_result - &(&p_carry * &p_limbs);
        let p_witness_low = self.witness_low.iter().into();
        let p_witness_high = self.witness_high.iter().into();
        eval_field_operation::<AB, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high);

        // Range checks for the result, carry, and witness columns.
        builder.slice_range_check_u8(&self.result, shard.clone(), is_real.clone());
        builder.slice_range_check_u8(&self.carry, shard.clone(), is_real.clone());
        builder.slice_range_check_u8(p_witness_low.coefficients(), shard.clone(), is_real.clone());
        builder.slice_range_check_u8(p_witness_high.coefficients(), shard, is_real);
    }
}

#[cfg(test)]
mod tests {
    use core::{
        borrow::{Borrow, BorrowMut},
        mem::size_of,
    };

    use num::{bigint::RandBigInt, BigUint};
    use p3_air::{Air, BaseAir};
    use p3_baby_bear::BabyBear;
    use p3_field::{Field, PrimeField32};
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use rand::thread_rng;
    use wp1_derive::AlignedBorrow;

    use super::{FieldOpCols, FieldOperation, Limbs};

    use crate::{air::MachineAir, utils::ec::weierstrass::bls12_381::Bls12381BaseField};

    use crate::bytes::event::ByteRecord;
    use crate::operations::field::params::FieldParameters;
    use crate::runtime::Program;
    use crate::stark::StarkGenericConfig;
    use crate::utils::ec::edwards::ed25519::Ed25519BaseField;
    use crate::utils::ec::weierstrass::secp256k1::Secp256k1BaseField;
    use crate::utils::{
        pad_to_power_of_two_nongeneric, uni_stark_prove as prove, uni_stark_verify as verify,
        BabyBearPoseidon2,
    };
    use crate::{air::SP1AirBuilder, runtime::ExecutionRecord};
    use p3_field::AbstractField;

    #[derive(AlignedBorrow, Debug, Clone)]
    pub struct TestCols<T, P: FieldParameters> {
        pub a: Limbs<T, P::NB_LIMBS>,
        pub b: Limbs<T, P::NB_LIMBS>,
        pub a_op_b: FieldOpCols<T, P>,
    }

    struct FieldOpChip<P: FieldParameters> {
        pub(crate) operation: FieldOperation,
        pub(crate) _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> FieldOpChip<P> {
        pub(crate) fn new(operation: FieldOperation) -> Self {
            Self {
                operation,
                _phantom: std::marker::PhantomData,
            }
        }
    }

    impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for FieldOpChip<P> {
        type Record = ExecutionRecord;

        type Program = Program;

        fn name(&self) -> String {
            format!("FieldOp{:?}", self.operation)
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            output: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            let mut rng = thread_rng();
            let num_rows = 1 << 8;
            let mut operands: Vec<(BigUint, BigUint)> = (0..num_rows - 5)
                .map(|_| {
                    let a = rng.gen_biguint(P::nb_bits() as u64) % &P::modulus();
                    let b = rng.gen_biguint(P::nb_bits() as u64) % &P::modulus();
                    (a, b)
                })
                .collect();

            // Hardcoded edge cases. We purposely include 0 / 0. While mathematically, that is not
            // allowed, we allow it in our implementation so padded rows can be all 0.
            operands.extend(vec![
                (BigUint::from(0u32), BigUint::from(0u32)),
                (BigUint::from(0u32), BigUint::from(1u32)),
                (BigUint::from(1u32), BigUint::from(2u32)),
                (BigUint::from(4u32), BigUint::from(5u32)),
                (BigUint::from(10u32), BigUint::from(19u32)),
            ]);

            let num_test_cols = <FieldOpChip<P> as BaseAir<F>>::width(self);

            let rows = operands
                .iter()
                .map(|(a, b)| {
                    let mut blu_events = Vec::new();
                    let mut row = vec![F::zero(); num_test_cols];
                    let cols: &mut TestCols<F, P> = row.as_mut_slice().borrow_mut();
                    cols.a = P::to_limbs_field::<F>(a);
                    cols.b = P::to_limbs_field::<F>(b);
                    cols.a_op_b
                        .populate(&mut blu_events, 1, a, b, self.operation);
                    output.add_byte_lookup_events(blu_events);
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

    impl<F: Field, P: FieldParameters> BaseAir<F> for FieldOpChip<P> {
        fn width(&self) -> usize {
            size_of::<TestCols<u8, P>>()
        }
    }

    impl<AB, P: FieldParameters> Air<AB> for FieldOpChip<P>
    where
        AB: SP1AirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &TestCols<AB::Var, P> = (*local).borrow();
            local.a_op_b.eval(
                builder,
                &local.a,
                &local.b,
                self.operation,
                AB::F::one(),
                AB::F::one(),
            );

            // A dummy constraint to keep the degree 3.
            #[allow(clippy::eq_op)]
            builder.assert_zero(
                local.a[0] * local.b[0] * local.a[0] - local.a[0] * local.b[0] * local.a[0],
            )
        }
    }

    fn generate_trace_for<F: FieldParameters>() {
        for op in [
            FieldOperation::Add,
            FieldOperation::Sub,
            FieldOperation::Mul,
            FieldOperation::Div,
        ]
        .iter()
        {
            println!("op: {:?}", op);
            let chip: FieldOpChip<F> = FieldOpChip::new(*op);
            let shard = ExecutionRecord::default();
            let _: RowMajorMatrix<BabyBear> =
                chip.generate_trace(&shard, &mut ExecutionRecord::default());
            // println!("{:?}", trace.values)
        }
    }

    fn prove_babybear_for<F: FieldParameters>() {
        let config = BabyBearPoseidon2::new();

        for op in [
            FieldOperation::Add,
            FieldOperation::Sub,
            FieldOperation::Mul,
            FieldOperation::Div,
        ]
        .iter()
        {
            println!("op: {:?}", op);

            let mut challenger = config.challenger();

            let chip: FieldOpChip<F> = FieldOpChip::new(*op);
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
        generate_trace_for::<Secp256k1BaseField>();
    }

    #[test]
    fn prove_babybear() {
        prove_babybear_for::<Ed25519BaseField>();
        prove_babybear_for::<Bls12381BaseField>();
        prove_babybear_for::<Secp256k1BaseField>();
    }
}
