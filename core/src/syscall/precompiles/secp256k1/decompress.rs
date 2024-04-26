use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use std::fmt::Debug;

use elliptic_curve::point::DecompressPoint;
use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::subtle::Choice;
use hybrid_array::typenum::Unsigned;
use hybrid_array::Array;
use num::{BigUint, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use serde::{Deserialize, Serialize};
use wp1_derive::AlignedBorrow;

use crate::air::{BaseAirBuilder, MachineAir, SP1AirBuilder};
use crate::memory::{MemoryReadCols, MemoryWriteCols};
use crate::operations::field::field_op::{FieldOpCols, FieldOperation};
use crate::operations::field::field_sqrt::FieldSqrtCols;
use crate::operations::field::params::{Limbs, DEFAULT_NUM_LIMBS_T, WORDS_FIELD_ELEMENT};
use crate::runtime::{
    ExecutionRecord, MemoryReadRecord, MemoryWriteRecord, Program, Syscall, SyscallCode,
    SyscallContext,
};
use crate::stark::Secp256k1Parameters;
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::weierstrass::secp256k1::{secp256k1_sqrt, Secp256k1BaseField};
use crate::utils::ec::weierstrass::WeierstrassParameters;
use crate::utils::ec::AffinePoint;
use crate::utils::{
    bytes_to_words_le_vec, limbs_from_access, limbs_from_prev_access, pad_rows,
    words_to_bytes_le_vec,
};

/// This function decompresses a compressed representation of an elliptic curve
/// point from Secp256k1.
///
/// Note that this function does not follow the specification from
/// [SEC1](https://www.secg.org/sec1-v2.pdf) paragraphs 2.3.3 and 2.3.4. See
/// also issue #139.
///
/// Instead, we receive the `x` coordinate as its own big-endian byte array, and
/// separately a single bit that is non-zero if the `y` coordinate is odd.
pub fn secp256k1_decompress(bytes_be: &[u8], sign: u32) -> AffinePoint<Secp256k1Parameters> {
    let computed_point =
        k256::AffinePoint::decompress(bytes_be.into(), Choice::from(sign as u8)).unwrap();
    let point = computed_point.to_encoded_point(false);

    let x = BigUint::from_bytes_be(point.x().unwrap());
    let y = BigUint::from_bytes_be(point.y().unwrap());
    AffinePoint::new(x, y)
}

/// Secp256k1 elliptic curve point decompress event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secp256k1DecompressEvent {
    pub shard: u32,
    pub clk: u32,
    pub ptr: u32,
    pub is_odd: bool,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub x_bytes: Array<u8, DEFAULT_NUM_LIMBS_T>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub decompressed_y_bytes: Array<u8, DEFAULT_NUM_LIMBS_T>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub x_memory_records: Array<MemoryReadRecord, WORDS_FIELD_ELEMENT<DEFAULT_NUM_LIMBS_T>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub y_memory_records: Array<MemoryWriteRecord, WORDS_FIELD_ELEMENT<DEFAULT_NUM_LIMBS_T>>,
}

pub fn create_secp256k1_decompress_event(
    rt: &mut SyscallContext<'_>,
    slice_ptr: u32,
    is_odd: u32,
) -> Secp256k1DecompressEvent {
    let start_clk = rt.clk;
    assert!(slice_ptr % 4 == 0, "slice_ptr must be 4-byte aligned");
    assert!(is_odd <= 1, "is_odd must be 0 or 1");

    let num_limbs = DEFAULT_NUM_LIMBS_T::USIZE;
    let num_words_field_element = WORDS_FIELD_ELEMENT::<DEFAULT_NUM_LIMBS_T>::USIZE;

    let (x_memory_records, x_vec) =
        rt.mr_slice(slice_ptr + (num_limbs as u32), num_words_field_element);

    let x_bytes = words_to_bytes_le_vec(&x_vec);
    let mut x_bytes_be = x_bytes.clone();
    x_bytes_be.reverse();

    let computed_point: AffinePoint<Secp256k1Parameters> =
        secp256k1_decompress(&x_bytes_be, is_odd);

    let mut decompressed_y_bytes = computed_point.y.to_bytes_le();
    decompressed_y_bytes.resize(num_limbs, 0u8);

    let y_words = bytes_to_words_le_vec(&decompressed_y_bytes);
    let y_memory_records = (&rt.mw_slice(slice_ptr, &y_words)[..]).try_into().unwrap();

    Secp256k1DecompressEvent {
        shard: rt.current_shard(),
        clk: start_clk,
        ptr: slice_ptr,
        is_odd: is_odd != 0,
        x_bytes: (&x_bytes[..]).try_into().unwrap(),
        decompressed_y_bytes: (&decompressed_y_bytes[..]).try_into().unwrap(),
        x_memory_records: (&x_memory_records[..]).try_into().unwrap(),
        y_memory_records,
    }
}

impl Syscall for Secp256k1DecompressChip {
    fn execute(&self, rt: &mut SyscallContext<'_>, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_secp256k1_decompress_event(rt, arg1, arg2);
        rt.record_mut().secp256k1_decompress_events.push(event);
        None
    }
}

/// A set of columns to decompress a compressed Secp256k1 elliptic curve point.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Secp256k1DecompressCols<T> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub ptr: T,
    pub is_odd: T,
    pub x_access: Array<MemoryReadCols<T>, WORDS_FIELD_ELEMENT<DEFAULT_NUM_LIMBS_T>>,
    pub y_access: Array<MemoryWriteCols<T>, WORDS_FIELD_ELEMENT<DEFAULT_NUM_LIMBS_T>>,
    pub(crate) x_2: FieldOpCols<T, DEFAULT_NUM_LIMBS_T>,
    pub(crate) x_3: FieldOpCols<T, DEFAULT_NUM_LIMBS_T>,
    pub(crate) x_3_plus_b: FieldOpCols<T, DEFAULT_NUM_LIMBS_T>,
    pub(crate) y: FieldSqrtCols<T, DEFAULT_NUM_LIMBS_T>,
    pub(crate) neg_y: FieldOpCols<T, DEFAULT_NUM_LIMBS_T>,
    pub(crate) y_least_bits: [T; 8],
}

/// A chip implementing Secp256k1 elliptic curve point decompression.
///
/// Note that this chip does not follow the specification from
/// [SEC1](https://www.secg.org/sec1-v2.pdf) paragraphs 2.3.3 and 2.3.4. See
/// also issue #139.
///
/// Instead, we receive the `x` coordinate as its own big-endian byte array, and
/// separately a single bit that is non-zero if the `y` coordinate is odd.
#[derive(Default)]
pub struct Secp256k1DecompressChip;

impl Secp256k1DecompressChip {
    pub fn new() -> Self {
        Self
    }

    fn populate_field_ops<F: PrimeField32>(cols: &mut Secp256k1DecompressCols<F>, x: &BigUint) {
        // Y = sqrt(x^3 + b)
        let x_2 =
            cols.x_2
                .populate::<Secp256k1BaseField>(&x.clone(), &x.clone(), FieldOperation::Mul);
        let x_3 = cols
            .x_3
            .populate::<Secp256k1BaseField>(&x_2, x, FieldOperation::Mul);
        let b = Secp256k1Parameters::b_int();
        let x_3_plus_b =
            cols.x_3_plus_b
                .populate::<Secp256k1BaseField>(&x_3, &b, FieldOperation::Add);

        let y = cols
            .y
            .populate::<Secp256k1BaseField>(&x_3_plus_b, secp256k1_sqrt);

        let zero = BigUint::zero();
        cols.neg_y
            .populate::<Secp256k1BaseField>(&zero, &y, FieldOperation::Sub);
        // Decompose bits of least significant Y byte
        let y_bytes = y.to_bytes_le();

        let y_lsb = if y_bytes.is_empty() { 0 } else { y_bytes[0] };
        for i in 0..8 {
            cols.y_least_bits[i] = F::from_canonical_u32(u32::from((y_lsb >> i) & 1));
        }
    }
}

impl<F: PrimeField32> MachineAir<F> for Secp256k1DecompressChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Secp256k1Decompress".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();

        for event in input.secp256k1_decompress_events.iter() {
            let mut row = [F::zero(); size_of::<Secp256k1DecompressCols<u8>>()];
            let cols: &mut Secp256k1DecompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.is_real = F::from_bool(true);
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.ptr = F::from_canonical_u32(event.ptr);
            cols.is_odd = F::from_canonical_u32(u32::from(event.is_odd));

            let x = BigUint::from_bytes_le(&event.x_bytes);
            Self::populate_field_ops(cols, &x);

            for i in 0..cols.x_access.len() {
                cols.x_access[i].populate(event.x_memory_records[i], &mut new_byte_lookup_events);
            }
            for i in 0..cols.y_access.len() {
                cols.y_access[i].populate(event.y_memory_records[i], &mut new_byte_lookup_events);
            }

            rows.push(row);
        }
        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); size_of::<Secp256k1DecompressCols<u8>>()];
            let cols: &mut Secp256k1DecompressCols<F> = row.as_mut_slice().borrow_mut();

            // take X of the generator as a dummy value to make sure Y^2 = X^3 + b holds
            let dummy_value = Secp256k1Parameters::generator().0;
            let dummy_bytes = dummy_value.to_bytes_le();
            let words = bytes_to_words_le_vec(&dummy_bytes);
            for i in 0..cols.x_access.len() {
                cols.x_access[i].access.value = words[i].into();
            }

            Self::populate_field_ops(cols, &dummy_value);
            row
        });

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            size_of::<Secp256k1DecompressCols<u8>>(),
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.secp256k1_decompress_events.is_empty()
    }
}

impl<F> BaseAir<F> for Secp256k1DecompressChip {
    fn width(&self) -> usize {
        size_of::<Secp256k1DecompressCols<u8>>()
    }
}

impl<AB> Air<AB> for Secp256k1DecompressChip
where
    AB: SP1AirBuilder,
    Limbs<AB::Var>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let row: &Secp256k1DecompressCols<AB::Var> = (*row).borrow();

        let num_limbs = DEFAULT_NUM_LIMBS_T::USIZE;
        let num_words_field_element = num_limbs / 4;

        builder.assert_bool(row.is_odd);

        let x: Limbs<AB::Var> = limbs_from_prev_access(&row.x_access);
        row.x_2
            .eval::<AB, Secp256k1BaseField, _, _>(builder, &x, &x, FieldOperation::Mul);
        row.x_3.eval::<AB, Secp256k1BaseField, _, _>(
            builder,
            &row.x_2.result,
            &x,
            FieldOperation::Mul,
        );
        let b = Secp256k1Parameters::b_int();
        let b_const = Secp256k1BaseField::to_limbs_field::<AB::F>(&b);
        row.x_3_plus_b.eval::<AB, Secp256k1BaseField, _, _>(
            builder,
            &row.x_3.result,
            &b_const,
            FieldOperation::Add,
        );
        row.y
            .eval::<AB, Secp256k1BaseField>(builder, &row.x_3_plus_b.result);
        row.neg_y.eval::<AB, Secp256k1BaseField, _, _>(
            builder,
            &[AB::Expr::zero()].iter(),
            &row.y.multiplication.result,
            FieldOperation::Sub,
        );

        // Constrain decomposition of least significant byte of Y into `y_least_bits`
        for i in 0..8 {
            builder.when(row.is_real).assert_bool(row.y_least_bits[i]);
        }
        let y_least_byte = row.y.multiplication.result[0];
        let powers_of_two = [1, 2, 4, 8, 16, 32, 64, 128].map(AB::F::from_canonical_u32);
        let recomputed_byte: AB::Expr = row
            .y_least_bits
            .iter()
            .zip(powers_of_two)
            .map(|(p, b)| (*p).into() * b)
            .sum();
        builder
            .when(row.is_real)
            .assert_eq(recomputed_byte, y_least_byte);

        // Interpret the lowest bit of Y as whether it is odd or not.
        let y_is_odd = row.y_least_bits[0];

        let y_limbs: Limbs<AB::Var> = limbs_from_access(&row.y_access);
        builder
            .when(row.is_real)
            .when_ne(y_is_odd, AB::Expr::one() - row.is_odd)
            .assert_all_eq(row.y.multiplication.result, y_limbs);

        builder
            .when(row.is_real)
            .when_ne(y_is_odd, row.is_odd)
            .assert_all_eq(row.neg_y.result, y_limbs);

        for i in 0..num_words_field_element {
            builder.eval_memory_access(
                row.shard,
                row.clk,
                row.ptr.into() + AB::F::from_canonical_u32((i as u32) * 4 + num_limbs as u32),
                &row.x_access[i],
                row.is_real,
            );
        }
        for i in 0..num_words_field_element {
            builder.eval_memory_access(
                row.shard,
                row.clk,
                row.ptr.into() + AB::F::from_canonical_u32((i as u32) * 4),
                &row.y_access[i],
                row.is_real,
            );
        }

        builder.receive_syscall(
            row.shard,
            row.clk,
            AB::F::from_canonical_u32(SyscallCode::SECP256K1_DECOMPRESS.syscall_id()),
            row.ptr,
            row.is_odd,
            row.is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use crate::utils::tests::SECP256K1_DECOMPRESS_ELF;
    use crate::utils::{
        run_test_io, {self},
    };
    use crate::{Program, SP1Stdin};

    #[test]
    fn test_weierstrass_secp256k1_decompress() {
        utils::setup_logger();

        let mut rng = StdRng::seed_from_u64(2);

        let secret_key = k256::SecretKey::random(&mut rng);
        let public_key = secret_key.public_key();
        let encoded = public_key.to_encoded_point(false);
        let decompressed = encoded.as_bytes();
        let compressed = public_key.to_sec1_bytes();

        let inputs = SP1Stdin::from(&compressed);

        let mut proof = run_test_io(Program::from(SECP256K1_DECOMPRESS_ELF), inputs).unwrap();
        let mut result = [0; 65];
        proof.public_values.read_slice(&mut result);
        assert_eq!(result, decompressed);
    }
}
