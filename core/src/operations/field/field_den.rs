use std::fmt::Debug;

use hybrid_array::{typenum::Unsigned, Array};
use num::BigUint;
use p3_field::PrimeField32;
use wp1_derive::AlignedBorrow;

use super::params::{FieldParameters, Limbs, WITNESS_LIMBS};
use super::util::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs};
use super::util_air::eval_field_operation;
use crate::air::Polynomial;
use crate::air::SP1AirBuilder;
use crate::bytes::event::ByteRecord;

/// A set of columns to compute `FieldDen(a, b)` where `a`, `b` are field elements.
///
/// `a / (1 + b)` if `sign`
/// `a / (1 - b) ` if `!sign`
///
/// *Safety*: the operation assumes that the denominators are never zero. It is the responsibility
/// of the caller to ensure that condition.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldDenCols<T, P: FieldParameters> {
    /// The result of `a den b`, where a, b are field elements
    pub result: Limbs<T, P::NB_LIMBS>,
    pub(crate) carry: Limbs<T, P::NB_LIMBS>,
    pub(crate) witness_low: Array<T, WITNESS_LIMBS<P::NB_LIMBS>>,
    pub(crate) witness_high: Array<T, WITNESS_LIMBS<P::NB_LIMBS>>,
}

impl<F: PrimeField32, P: FieldParameters> FieldDenCols<F, P> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        shard: u32,
        a: &BigUint,
        b: &BigUint,
        sign: bool,
    ) -> BigUint {
        let p = P::modulus();
        let minus_b_int = &p - b;
        let b_signed = if sign { b.clone() } else { minus_b_int };
        let denominator = (b_signed + 1u32) % &(p.clone());
        let den_inv = denominator.modpow(&(&p - 2u32), &p);
        let result = (a * &den_inv) % &p;
        debug_assert_eq!(&den_inv * &denominator % &p, BigUint::from(1u32));
        debug_assert!(result < p);

        let equation_lhs = if sign {
            b * &result + &result
        } else {
            b * &result + a
        };
        let equation_rhs = if sign { a.clone() } else { result.clone() };
        let carry = (&equation_lhs - &equation_rhs) / &p;
        debug_assert!(carry < p);
        debug_assert_eq!(&carry * &p, &equation_lhs - &equation_rhs);

        let p_a: Polynomial<F> = P::to_limbs_field::<F>(a).into();
        let p_b: Polynomial<F> = P::to_limbs_field::<F>(b).into();
        let p_p: Polynomial<F> = P::to_limbs_field::<F>(&p).into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F>(&result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F>(&carry).into();

        // Compute the vanishing polynomial.
        let vanishing_poly = if sign {
            &p_b * &p_result + &p_result - &p_a - &p_carry * &p_p
        } else {
            &p_b * &p_result + &p_a - &p_result - &p_carry * &p_p
        };
        debug_assert_eq!(vanishing_poly.degree(), WITNESS_LIMBS::<P::NB_LIMBS>::USIZE);

        let p_witness = compute_root_quotient_and_shift(
            &vanishing_poly,
            P::WITNESS_OFFSET,
            P::NB_BITS_PER_LIMB as u32,
        );
        let (p_witness_low, p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

        self.result = p_result.try_into().unwrap();
        self.carry = p_carry.try_into().unwrap();
        self.witness_low = (&p_witness_low[..]).try_into().unwrap();
        self.witness_high = (&p_witness_high[..]).try_into().unwrap();

        // Range checks
        record.add_u8_range_checks_field(shard, &self.result);
        record.add_u8_range_checks_field(shard, &self.carry);
        record.add_u8_range_checks_field(shard, &self.witness_low);
        record.add_u8_range_checks_field(shard, &self.witness_high);

        result
    }
}

impl<V: Copy, P: FieldParameters> FieldDenCols<V, P> {
    pub fn eval<
        AB: SP1AirBuilder<Var = V>,
        EShard: Into<AB::Expr> + Clone,
        ER: Into<AB::Expr> + Clone,
    >(
        &self,
        builder: &mut AB,
        a: &Limbs<AB::Var, P::NB_LIMBS>,
        b: &Limbs<AB::Var, P::NB_LIMBS>,
        sign: bool,
        shard: EShard,
        is_real: ER,
    ) where
        V: Into<AB::Expr>,
    {
        let p_a = Polynomial::from(a.clone());
        let p_b = (b.clone()).into();
        let p_result = self.result.clone().into();
        let p_carry: Polynomial<_> = self.carry.clone().into();

        // Compute the vanishing polynomial:
        //      lhs(x) = sign * (b(x) * result(x) + result(x)) + (1 - sign) * (b(x) * result(x) + a(x))
        //      rhs(x) = sign * a(x) + (1 - sign) * result(x)
        //      lhs(x) - rhs(x) - carry(x) * p(x)
        let p_equation_lhs = if sign {
            &p_b * &p_result + &p_result
        } else {
            &p_b * &p_result + &p_a
        };
        let p_equation_rhs = if sign { p_a } else { p_result };

        let p_lhs_minus_rhs = &p_equation_lhs - &p_equation_rhs;
        let p_limbs = P::modulus_field_iter::<AB::F>()
            .map(AB::Expr::from)
            .collect();

        let p_vanishing = p_lhs_minus_rhs - &p_carry * &p_limbs;

        let p_witness_low = self.witness_low.iter().into();
        let p_witness_high = self.witness_high.iter().into();

        eval_field_operation::<AB, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high);

        // Range checks for the result, carry, and witness columns.
        builder.slice_range_check_u8(&self.result, shard.clone(), is_real.clone());
        builder.slice_range_check_u8(&self.carry, shard.clone(), is_real.clone());
        builder.slice_range_check_u8(&self.witness_low, shard.clone(), is_real.clone());
        builder.slice_range_check_u8(&self.witness_high, shard, is_real);
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

    use super::{FieldDenCols, Limbs};

    use crate::{
        air::MachineAir,
        utils::ec::weierstrass::{bls12_381::Bls12381BaseField, secp256k1::Secp256k1BaseField},
    };

    use crate::operations::field::params::FieldParameters;
    use crate::runtime::Program;
    use crate::stark::StarkGenericConfig;
    use crate::utils::ec::edwards::ed25519::Ed25519BaseField;
    use crate::utils::BabyBearPoseidon2;
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use crate::{air::SP1AirBuilder, runtime::ExecutionRecord};
    use p3_field::AbstractField;
    #[derive(Debug, Clone, AlignedBorrow)]
    pub struct TestCols<T, P: FieldParameters> {
        pub a: Limbs<T, P::NB_LIMBS>,
        pub b: Limbs<T, P::NB_LIMBS>,
        pub a_den_b: FieldDenCols<T, P>,
    }

    struct FieldDenChip<P: FieldParameters> {
        pub(crate) sign: bool,
        pub(crate) _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> FieldDenChip<P> {
        pub(crate) fn new(sign: bool) -> Self {
            Self {
                sign,
                _phantom: std::marker::PhantomData,
            }
        }
    }

    impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for FieldDenChip<P> {
        type Record = ExecutionRecord;

        type Program = Program;

        fn name(&self) -> String {
            "FieldDen".to_string()
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            output: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            let mut rng = thread_rng();
            let num_rows = 1 << 8;
            let mut operands: Vec<(BigUint, BigUint)> = (0..num_rows - 4)
                .map(|_| {
                    let a = rng.gen_biguint(P::nb_bits() as u64) % &P::modulus();
                    let b = rng.gen_biguint(P::nb_bits() as u64) % &P::modulus();
                    (a, b)
                })
                .collect();
            // Hardcoded edge cases.
            operands.extend(vec![
                (BigUint::from(0u32), BigUint::from(0u32)),
                (BigUint::from(1u32), BigUint::from(2u32)),
                (BigUint::from(4u32), BigUint::from(5u32)),
                (BigUint::from(10u32), BigUint::from(19u32)),
            ]);
            // It is important that the number of rows is an exact power of 2,
            // otherwise the padding will not work correctly.
            assert_eq!(operands.len(), num_rows);

            let num_test_cols = <FieldDenChip<P> as BaseAir<F>>::width(self);

            let rows = operands
                .iter()
                .map(|(a, b)| {
                    let mut row = vec![F::zero(); num_test_cols];
                    let cols: &mut TestCols<F, P> = row.as_mut_slice().borrow_mut();
                    cols.a = P::to_limbs_field::<F>(a);
                    cols.b = P::to_limbs_field::<F>(b);
                    cols.a_den_b.populate(output, 1, a, b, self.sign);
                    row
                })
                .collect::<Vec<_>>();
            // Convert the trace to a row major matrix.

            // Note we do not pad the trace here because we cannot just pad with all 0s.

            RowMajorMatrix::new(
                rows.into_iter().flatten().collect::<Vec<_>>(),
                num_test_cols,
            )
        }

        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<F: Field, P: FieldParameters> BaseAir<F> for FieldDenChip<P> {
        fn width(&self) -> usize {
            size_of::<TestCols<u8, P>>()
        }
    }

    impl<AB, P: FieldParameters> Air<AB> for FieldDenChip<P>
    where
        AB: SP1AirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &TestCols<AB::Var, P> = (*local).borrow();
            local.a_den_b.eval(
                builder,
                &local.a,
                &local.b,
                self.sign,
                AB::F::one(),
                AB::F::one(),
            );
        }
    }

    fn generate_trace_for<F: FieldParameters>() {
        let shard = ExecutionRecord::default();
        let chip: FieldDenChip<F> = FieldDenChip::new(true);
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    fn prove_babybear_for<F: FieldParameters>() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let shard = ExecutionRecord::default();

        let chip: FieldDenChip<F> = FieldDenChip::new(true);
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        // This it to test that the proof DOESN'T work if messed up.
        // let row = trace.row_mut(0);
        // row[0] = BabyBear::from_canonical_u8(0);
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
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
