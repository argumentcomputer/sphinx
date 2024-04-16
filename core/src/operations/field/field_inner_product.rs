use std::fmt::Debug;

use hybrid_array::typenum::Unsigned;
use hybrid_array::Array;
use num::{BigUint, Integer, Zero};
use p3_field::{AbstractField, PrimeField32};
use p3_maybe_rayon::prelude::*;
use wp1_derive::AlignedBorrow;

use super::params::{Limbs, WITNESS_LIMBS};
use super::util::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs};
use super::util_air::eval_field_operation;
use crate::air::{Polynomial, SP1AirBuilder};
use crate::utils::ec::field::FieldParameters;

/// A set of columns to compute `FieldInnerProduct(Vec<a>, Vec<b>)` where a, b are field elements.
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed
/// or made generic in the future.
///
/// TODO: There is an issue here here some fields in these columns must be range checked. This is
/// a known issue and will be fixed in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldInnerProductCols<T, P: FieldParameters> {
    /// The result of `a inner product b`, where a, b are field elements
    pub result: Limbs<T, P::NB_LIMBS>,
    pub(crate) carry: Limbs<T, P::NB_LIMBS>,
    pub(crate) witness_low: Array<T, WITNESS_LIMBS<P::NB_LIMBS>>,
    pub(crate) witness_high: Array<T, WITNESS_LIMBS<P::NB_LIMBS>>,
}

impl<F: PrimeField32, P: FieldParameters> FieldInnerProductCols<F, P> {
    pub fn populate(&mut self, a: &[BigUint], b: &[BigUint]) -> BigUint {
        let modulus = &P::modulus();
        let inner_product = a
            .par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| x * y)
            .reduce(BigUint::zero, |acc, partial| acc + partial);

        let (carry, result) = inner_product.div_rem(modulus);
        debug_assert!(&result < modulus);
        assert!(carry < (2u32 * modulus));
        assert_eq!(&carry * modulus, inner_product - &result);

        let p_modulus: Polynomial<F> = P::to_limbs_field::<F>(modulus).into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F>(&result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F>(&carry).into();

        let p_inner_product = a
            .par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| {
                Polynomial::from(P::to_limbs_field::<F>(x))
                    * Polynomial::from(P::to_limbs_field::<F>(y))
            })
            .reduce(
                || Polynomial::<F>::new(vec![F::zero()]),
                |acc, partial| acc + partial,
            );

        let p_vanishing = p_inner_product - &p_result - &p_carry * &p_modulus;
        assert_eq!(p_vanishing.degree(), WITNESS_LIMBS::<P::NB_LIMBS>::USIZE);

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
}

impl<V: Copy, P: FieldParameters> FieldInnerProductCols<V, P> {
    pub fn eval<AB: SP1AirBuilder<Var = V>, I: IntoIterator<Item = Limbs<AB::Var, P::NB_LIMBS>>>(
        &self,
        builder: &mut AB,
        a: I,
        b: I,
    ) where
        V: Into<AB::Expr>,
    {
        let p_result = self.result.clone().into();
        let p_carry: Polynomial<_> = self.carry.clone().into();

        let p_zero = Polynomial::<AB::Expr>::new(vec![AB::Expr::zero()]);

        let p_inner_product = a
            .into_iter()
            .zip(b.into_iter())
            .map(|(a, b)| Polynomial::from(a) * Polynomial::from(b))
            .fold(p_zero, |acc, partial| acc + partial);

        let p_inner_product_minus_result = &p_inner_product - &p_result;
        let p_limbs = P::modulus_field_iter::<AB::F>()
            .map(AB::Expr::from)
            .collect();
        // let p_carry_mul_modulus = &p_carry * &p_limbs;
        let p_vanishing = &p_inner_product_minus_result - &(&p_carry * &p_limbs);

        let p_witness_low = self.witness_low.iter().into();
        let p_witness_high = self.witness_high.iter().into();

        eval_field_operation::<AB, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high);
    }
}

#[cfg(test)]
mod tests {
    use core::borrow::{Borrow, BorrowMut};
    use core::mem::size_of;

    use num::bigint::RandBigInt;
    use num::BigUint;
    use p3_air::{Air, BaseAir};
    use p3_baby_bear::BabyBear;
    use p3_field::{Field, PrimeField32};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;
    use rand::thread_rng;
    use wp1_derive::AlignedBorrow;

    use super::{FieldInnerProductCols, Limbs};
    use crate::air::{MachineAir, SP1AirBuilder};
    use crate::runtime::{ExecutionRecord, Program};
    use crate::stark::StarkGenericConfig;
    use crate::utils::ec::edwards::ed25519::Ed25519BaseField;
    use crate::utils::ec::field::FieldParameters;
    use crate::utils::ec::weierstrass::bls12_381::Bls12381BaseField;
    use crate::utils::ec::weierstrass::secp256k1::Secp256k1BaseField;
    use crate::utils::{
        pad_to_power_of_two_nongeneric, uni_stark_prove as prove, uni_stark_verify as verify,
        BabyBearPoseidon2,
    };

    #[derive(AlignedBorrow, Debug, Clone)]
    pub struct TestCols<T, P: FieldParameters> {
        pub a: [Limbs<T, P::NB_LIMBS>; 1],
        pub b: [Limbs<T, P::NB_LIMBS>; 1],
        pub a_ip_b: FieldInnerProductCols<T, P>,
    }

    struct FieldIpChip<P: FieldParameters> {
        pub(crate) _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> FieldIpChip<P> {
        pub(crate) fn new() -> Self {
            Self {
                _phantom: std::marker::PhantomData,
            }
        }
    }

    impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for FieldIpChip<P> {
        type Record = ExecutionRecord;

        type Program = Program;

        fn name(&self) -> String {
            "FieldInnerProduct".to_string()
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            let mut rng = thread_rng();
            let num_rows = 1 << 8;
            let mut operands: Vec<(Vec<BigUint>, Vec<BigUint>)> = (0..num_rows - 4)
                .map(|_| {
                    let a = rng.gen_biguint(P::nb_bits() as u64) % &P::modulus();
                    let b = rng.gen_biguint(P::nb_bits() as u64) % &P::modulus();
                    (vec![a], vec![b])
                })
                .collect();

            operands.extend(vec![
                (vec![BigUint::from(0u32)], vec![BigUint::from(0u32)]),
                (vec![BigUint::from(0u32)], vec![BigUint::from(0u32)]),
                (vec![BigUint::from(0u32)], vec![BigUint::from(0u32)]),
                (vec![BigUint::from(0u32)], vec![BigUint::from(0u32)]),
            ]);
            let num_test_cols = <FieldIpChip<P> as BaseAir<F>>::width(self);
            let rows = operands
                .iter()
                .map(|(a, b)| {
                    let mut row = vec![F::zero(); num_test_cols];
                    let cols: &mut TestCols<F, P> = row.as_mut_slice().borrow_mut();
                    cols.a[0] = P::to_limbs_field::<F>(&a[0]);
                    cols.b[0] = P::to_limbs_field::<F>(&b[0]);
                    cols.a_ip_b.populate(a, b);
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

    impl<F: Field, P: FieldParameters> BaseAir<F> for FieldIpChip<P> {
        fn width(&self) -> usize {
            size_of::<TestCols<u8, P>>()
        }
    }

    impl<AB, P: FieldParameters> Air<AB> for FieldIpChip<P>
    where
        AB: SP1AirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &TestCols<AB::Var, P> = (*local).borrow();
            local
                .a_ip_b
                .eval::<AB, _>(builder, local.a.clone(), local.b.clone());

            // A dummy constraint to keep the degree 3.
            #[allow(clippy::eq_op)]
            builder.assert_zero(
                local.a[0][0] * local.b[0][0] * local.a[0][0]
                    - local.a[0][0] * local.b[0][0] * local.a[0][0],
            )
        }
    }

    fn generate_trace_for<F: FieldParameters>() {
        let shard = ExecutionRecord::default();
        let chip: FieldIpChip<F> = FieldIpChip::new();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    fn prove_babybear_for<F: FieldParameters>() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let shard = ExecutionRecord::default();

        let chip: FieldIpChip<F> = FieldIpChip::new();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
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
