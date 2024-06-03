use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use std::fmt::Debug;

use bls12_381::G1Affine;
use hybrid_array::{typenum::Unsigned, Array};
use num::{BigUint, One, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use serde::{Deserialize, Serialize};
use sphinx_derive::AlignedBorrow;

use crate::air::{AluAirBuilder, ByteAirBuilder, MemoryAirBuilder};
use crate::bytes::{ByteLookupEvent, ByteOpcode};
use crate::operations::field::params::FieldParameters;
use crate::operations::field::range::FieldRangeCols;
use crate::{
    air::{BaseAirBuilder, MachineAir},
    bytes::event::ByteRecord,
    memory::{MemoryCols, MemoryReadCols, MemoryWriteCols},
    operations::field::{
        field_op::{FieldOpCols, FieldOperation},
        field_sqrt::FieldSqrtCols,
        params::Limbs,
    },
    runtime::{
        ExecutionRecord, MemoryReadRecord, MemoryWriteRecord, Program, Syscall, SyscallCode,
        SyscallContext,
    },
    utils::{
        bytes_to_words_le_vec,
        ec::{
            weierstrass::{
                bls12_381::{bls12381_sqrt, Bls12381BaseField, Bls12381Parameters},
                SwCurve, WeierstrassParameters,
            },
            AffinePoint,
        },
        limbs_from_access, limbs_from_prev_access, pad_rows, words_to_bytes_le_vec,
    },
};

use super::{BLS12_381_NUM_LIMBS, BLS12_381_NUM_WORDS_FOR_FIELD};

/// This function decompresses a compressed BLS12-381 G1 elliptic curve point.
///
/// It receives a big-endian byte array following the zcash serialization format, defined at:
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-11.html#name-zcash-serialization-format-
pub fn bls12_381_g1_decompress(bytes_be: &[u8]) -> AffinePoint<SwCurve<Bls12381Parameters>> {
    let arr_be: [u8; 48] = bytes_be.try_into().expect("Invalid input length");

    let Some(point): Option<G1Affine> = G1Affine::from_compressed(&arr_be).into() else {
        panic!("Invalid coordinate for G1 point: {:?}", arr_be);
    };

    if point.is_identity().into() {
        // the conventional representation of the infinity point
        return AffinePoint::new(BigUint::zero(), BigUint::one());
    }

    let x = BigUint::from_bytes_be(&point.x.to_bytes()[..]);
    let y = BigUint::from_bytes_be(&point.y.to_bytes()[..]);
    AffinePoint::new(x, y)
}

/// BLS12-381 G1 elliptic curve point decompress event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bls12381G1DecompressEvent {
    pub shard: u32,
    pub clk: u32,
    pub ptr: u32,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub x_bytes: Array<u8, BLS12_381_NUM_LIMBS>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub decompressed_y_bytes: Array<u8, BLS12_381_NUM_LIMBS>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub x_memory_records: Array<MemoryReadRecord, BLS12_381_NUM_WORDS_FOR_FIELD>,
    pub x_msb_memory_record: MemoryWriteRecord,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub y_memory_records: Array<MemoryWriteRecord, BLS12_381_NUM_WORDS_FOR_FIELD>,
}

pub fn create_bls12381_g1_decompress_event(
    rt: &mut SyscallContext<'_>,
    slice_ptr: u32,
) -> Bls12381G1DecompressEvent {
    let start_clk = rt.clk;
    assert!(slice_ptr % 4 == 0, "slice_ptr must be 4-byte aligned");

    let num_limbs = BLS12_381_NUM_LIMBS::USIZE;
    let num_words_field_element = BLS12_381_NUM_WORDS_FOR_FIELD::USIZE;

    let (x_memory_records, x_vec) =
        rt.mr_slice(slice_ptr + (num_limbs as u32), num_words_field_element);

    let x_bytes = words_to_bytes_le_vec(&x_vec);
    let mut x_bytes_be = x_bytes.clone();
    x_bytes_be.reverse();

    let computed_point: AffinePoint<SwCurve<Bls12381Parameters>> =
        bls12_381_g1_decompress(&x_bytes_be);

    let mut decompressed_y_bytes = computed_point.y.to_bytes_le();
    decompressed_y_bytes.resize(num_limbs, 0u8);

    let y_words = bytes_to_words_le_vec(&decompressed_y_bytes);
    let y_memory_records = (&rt.mw_slice(slice_ptr, &y_words)[..]).try_into().unwrap();

    // Increase the clk by 1 to write over the x MSB words
    rt.clk += 1;

    let mut decompressed_x_bytes = computed_point.x.to_bytes_le();
    decompressed_x_bytes.resize(num_limbs, 0u8);
    let x_msb_word = u32::from_le_bytes(decompressed_x_bytes[num_limbs - 4..].try_into().unwrap());
    let x_msb_memory_record = rt.mw(slice_ptr + (2 * num_limbs as u32) - 4, x_msb_word);

    Bls12381G1DecompressEvent {
        shard: rt.current_shard(),
        clk: start_clk,
        ptr: slice_ptr,
        x_bytes: (&decompressed_x_bytes[..]).try_into().unwrap(),
        decompressed_y_bytes: (&decompressed_y_bytes[..]).try_into().unwrap(),
        x_memory_records: (&x_memory_records[..]).try_into().unwrap(),
        x_msb_memory_record,
        y_memory_records,
    }
}

impl Syscall for Bls12381G1DecompressChip {
    fn execute(&self, rt: &mut SyscallContext<'_>, arg1: u32, _arg2: u32) -> Option<u32> {
        let event = create_bls12381_g1_decompress_event(rt, arg1);
        rt.record_mut().bls12381_g1_decompress_events.push(event);
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}

/// A set of columns to decompress a compressed BLS12-381 elliptic curve point.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Bls12381G1DecompressCols<T> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub ptr: T,
    pub x_access: Array<MemoryReadCols<T>, BLS12_381_NUM_WORDS_FOR_FIELD>,
    pub x_msb_access: MemoryWriteCols<T>,
    pub y_access: Array<MemoryWriteCols<T>, BLS12_381_NUM_WORDS_FOR_FIELD>,
    pub(crate) unmasked_range_x: FieldRangeCols<T, Bls12381BaseField>,
    pub(crate) x_msbits: [T; 8],
    pub(crate) x_2: FieldOpCols<T, Bls12381BaseField>,
    pub(crate) x_3: FieldOpCols<T, Bls12381BaseField>,
    pub(crate) x_3_plus_b: FieldOpCols<T, Bls12381BaseField>,
    pub(crate) y: FieldSqrtCols<T, Bls12381BaseField>,
    pub(crate) two_y: FieldOpCols<T, Bls12381BaseField>,
    pub(crate) neg_y: FieldOpCols<T, Bls12381BaseField>,
    pub(crate) two_y_lsb: T,
}

/// A chip implementing BLS12-381 G1 elliptic curve point decompression.
///
/// The chip receives the full compressed bits from the syscall via the `ptr`,
/// including compression flags in the most significant bits of `x`. The flags
/// are handled inside the AIR constraints. The handling of the point at
/// infinity is done out-of-circuit in the `syscall_bls12381_g1_decompress`
/// function for now.
///
/// To check whether `y > (p-1)/2`, we instead calculate the value of `2*y` and
/// check its parity by looking at its LSBit. If `2*y` is even, then `y <=
/// (p-1)/2` and if `2*y` is odd, then `y > (p-1)/2` due to the behavior of
/// modular reduction. This check is cheaper to do in-circuit than a full bit
/// decomposition.
///
/// Additional care is taken to ensure that the MSByte of `x` is overwritten to
/// clear any compression flags, by writing to the correct memory address after
/// reading from it to fetch the bit flags information for the circuit.
#[derive(Default)]
pub struct Bls12381G1DecompressChip;

impl Bls12381G1DecompressChip {
    pub fn new() -> Self {
        Self
    }

    fn populate_field_ops<F: PrimeField32>(
        record: &mut impl ByteRecord,
        shard: u32,
        cols: &mut Bls12381G1DecompressCols<F>,
        x: &BigUint,
    ) {
        // Y = sqrt(x^3 + b)
        cols.unmasked_range_x.populate(record, shard, x);
        let x_2 = cols.x_2.populate(record, shard, x, x, FieldOperation::Mul);
        let x_3 = cols
            .x_3
            .populate(record, shard, &x_2, x, FieldOperation::Mul);
        let b = Bls12381Parameters::b_int();
        let x_3_plus_b = cols
            .x_3_plus_b
            .populate(record, shard, &x_3, &b, FieldOperation::Add);

        let y = cols.y.populate(record, shard, &x_3_plus_b, bls12381_sqrt);

        let two_y = cols
            .two_y
            .populate(record, shard, &y, &y, FieldOperation::Add);

        let zero = BigUint::zero();
        cols.neg_y
            .populate(record, shard, &zero, &y, FieldOperation::Sub);

        // Byte-check the least significant 2*Y bit
        let two_y_bytes = Bls12381BaseField::to_limbs(&two_y);
        cols.two_y_lsb = F::from_canonical_u8(two_y_bytes[0] & 1);

        let and_event = ByteLookupEvent {
            shard,
            opcode: ByteOpcode::AND,
            a1: cols.two_y_lsb.as_canonical_u32(),
            a2: 0,
            b: u32::from(two_y_bytes[0]),
            c: 1,
        };
        record.add_byte_lookup_event(and_event);
    }
}

impl<F: PrimeField32> MachineAir<F> for Bls12381G1DecompressChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Bls12381G1Decompress".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();

        for event in input.bls12381_g1_decompress_events.iter() {
            let mut row = [F::zero(); size_of::<Bls12381G1DecompressCols<u8>>()];
            let cols: &mut Bls12381G1DecompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.is_real = F::from_bool(true);
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.ptr = F::from_canonical_u32(event.ptr);

            let x = BigUint::from_bytes_le(&event.x_bytes);
            Self::populate_field_ops(&mut new_byte_lookup_events, event.shard, cols, &x);

            // Get the previous value that still has the flags for the bit decomposition
            let x_msb = event.x_msb_memory_record.prev_value;
            for i in 0..8 {
                // Shift by 24 to get the MSBs (memory is in LE)
                cols.x_msbits[i] = F::from_canonical_u32((x_msb >> (i + 24)) & 1);
            }

            for i in 0..cols.x_access.len() {
                cols.x_access[i].populate(event.x_memory_records[i], &mut new_byte_lookup_events);
            }
            cols.x_msb_access
                .populate(event.x_msb_memory_record, &mut new_byte_lookup_events);
            for i in 0..cols.y_access.len() {
                cols.y_access[i].populate(event.y_memory_records[i], &mut new_byte_lookup_events);
            }

            rows.push(row);
        }
        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); size_of::<Bls12381G1DecompressCols<u8>>()];
            let cols: &mut Bls12381G1DecompressCols<F> = row.as_mut_slice().borrow_mut();

            // take X of the generator as a dummy value to make sure Y^2 = X^3 + b holds
            let dummy_value = Bls12381Parameters::generator().0;
            let dummy_bytes = dummy_value.to_bytes_le();
            let words = bytes_to_words_le_vec(&dummy_bytes);
            // Fill in the x values being used for constructing the dummy field operations
            for i in 0..cols.x_access.len() {
                cols.x_access[i].access.value = words[i].into();
            }
            cols.x_msb_access.access.value = words[11].into();

            Self::populate_field_ops(&mut vec![], 0, cols, &dummy_value);
            row
        });

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            size_of::<Bls12381G1DecompressCols<u8>>(),
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.bls12381_g1_decompress_events.is_empty()
    }
}

impl<F> BaseAir<F> for Bls12381G1DecompressChip {
    fn width(&self) -> usize {
        size_of::<Bls12381G1DecompressCols<u8>>()
    }
}

impl<AB> Air<AB> for Bls12381G1DecompressChip
where
    AB: AluAirBuilder + ByteAirBuilder,
    Limbs<AB::Var, BLS12_381_NUM_LIMBS>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let row: &Bls12381G1DecompressCols<AB::Var> = (*row).borrow();

        let num_limbs = BLS12_381_NUM_LIMBS::USIZE;
        let num_words_field_element = num_limbs / 4;

        let powers_of_two = [1, 2, 4, 8, 16, 32, 64, 128].map(AB::F::from_canonical_u32);

        for i in 0..8 {
            builder.when(row.is_real).assert_bool(row.x_msbits[i]);
        }
        let x_msbyte: AB::Var = row.x_msb_access.prev_value()[3];
        let recomputed_x_msbyte: AB::Expr = row
            .x_msbits
            .iter()
            .zip(powers_of_two)
            .map(|(p, b)| (*p).into() * b)
            .sum();
        builder
            .when(row.is_real)
            .assert_eq(recomputed_x_msbyte, x_msbyte);

        let compression_flag = row.x_msbits[7];
        // The compression flag must always be set
        builder.when(row.is_real).assert_one(compression_flag);

        // We handle the infinity case out-of-circuit for now, so assert infinity flag is never set
        // TODO: Handle the case where the infinity flag is set *in-circuit*, following the serialization specification
        let infinity_flag = row.x_msbits[6];
        builder.when(row.is_real).assert_zero(infinity_flag);

        let y_sign_flag = row.x_msbits[5];

        let mut x: Limbs<AB::Var, BLS12_381_NUM_LIMBS> = limbs_from_prev_access(&row.x_access);
        // Overwrite the MSByte with the overwritten value (with flags cleared)
        x[num_limbs - 1] = row.x_msb_access.value()[3];
        // Check the unmasked bytes pass a range check
        row.unmasked_range_x
            .eval(builder, &x, row.shard, row.is_real);

        row.x_2
            .eval(builder, &x, &x, FieldOperation::Mul, row.shard, row.is_real);
        row.x_3.eval(
            builder,
            &row.x_2.result,
            &x,
            FieldOperation::Mul,
            row.shard,
            row.is_real,
        );
        let b = Bls12381Parameters::b_int();
        let b_const = Bls12381BaseField::to_limbs_field::<AB::F>(&b);
        row.x_3_plus_b.eval(
            builder,
            &row.x_3.result,
            &b_const,
            FieldOperation::Add,
            row.shard,
            row.is_real,
        );

        row.y
            .eval(builder, &row.x_3_plus_b.result, &row.shard, &row.is_real);
        row.two_y.eval(
            builder,
            &row.y.multiplication.result,
            &row.y.multiplication.result,
            FieldOperation::Add,
            row.shard,
            row.is_real,
        );
        row.neg_y.eval(
            builder,
            &[AB::Expr::zero()].iter(),
            &row.y.multiplication.result,
            FieldOperation::Sub,
            row.shard,
            row.is_real,
        );

        // Constrain decomposition of least significant bit of 2*Y into `two_y_lsb`
        let two_y_least_byte = row.two_y.result[0];
        builder.assert_bool(row.two_y_lsb);
        builder.send_byte(
            ByteOpcode::AND.as_field::<AB::F>(),
            row.two_y_lsb,
            two_y_least_byte,
            AB::F::one(),
            row.shard,
            row.is_real,
        );

        // Instead of doing a range check on y to see if y > (p-1)/2 or not,
        // we calculate the parity of 2*y by checking its LSBit.
        // If 2*y is even, then y <= (p-1)/2 (i.e. y_sign_flag == 0),
        // if 2*y is odd, then y > (p-1)/2 (i.e. y_sign_flag == 1)
        let two_y_is_odd = row.two_y_lsb;

        let y_limbs: Limbs<AB::Var, BLS12_381_NUM_LIMBS> = limbs_from_access(&row.y_access);

        // If two_y_is_odd, then pick y if y_sign_flag is set
        builder
            .when(row.is_real)
            .when_ne(two_y_is_odd, AB::Expr::one() - y_sign_flag)
            .assert_all_eq(row.y.multiplication.result, y_limbs);

        // Otherwise, pick neg_y
        builder
            .when(row.is_real)
            .when_ne(two_y_is_odd, y_sign_flag)
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
        builder.eval_memory_access(
            row.shard,
            row.clk + AB::Expr::one(),
            row.ptr.into() + AB::F::from_canonical_u32((2 * num_limbs as u32) - 4),
            &row.x_msb_access,
            row.is_real,
        );

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
            AB::F::from_canonical_u32(SyscallCode::BLS12381_G1_DECOMPRESS.syscall_id()),
            row.ptr,
            AB::Expr::zero(),
            row.is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::bls12_381_g1_decompress;
    use crate::{
        io::SphinxStdin,
        operations::field::params::FieldParameters,
        runtime::{Instruction, Opcode, SyscallCode},
        stark::SwCurve,
        syscall::precompiles::bls12_381::BLS12_381_NUM_LIMBS,
        utils::{
            self, bytes_to_words_be_vec,
            ec::{
                weierstrass::{
                    bls12_381::{Bls12381BaseField, Bls12381Parameters},
                    WeierstrassParameters,
                },
                AffinePoint,
            },
            run_test_io, run_test_with_memory_inspection,
            tests::BLS12381_G1_DECOMPRESS_ELF,
            words_to_bytes_le_vec,
        },
        Program,
    };
    use bls12_381::G1Affine;
    use elliptic_curve::{group::Curve, Group as _};
    use hybrid_array::typenum::Unsigned;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const NUM_TEST_CASES: usize = 10;

    // Serialization flags
    const COMPRESSION_FLAG: u8 = 0b_1000_0000;
    const Y_SIGN_FLAG: u8 = 0b_0010_0000;

    #[test]
    fn test_bls12381_g1_decompress() {
        // This test checks that decompression of generator, 2x generator, 4x generator, etc. works.

        // Get the generator point.
        let mut point = {
            let (x, y) = <Bls12381Parameters as WeierstrassParameters>::generator();
            AffinePoint::<SwCurve<Bls12381Parameters>>::new(x, y)
        };
        for _ in 0..NUM_TEST_CASES {
            let compressed_point = {
                let mut result = [0u8; BLS12_381_NUM_LIMBS::USIZE];
                let x = point.x.to_bytes_le();
                result[..x.len()].copy_from_slice(&x);
                result.reverse();

                // Evaluate if y > -y
                let y = point.y.clone();
                let y_neg = Bls12381BaseField::modulus() - y.clone();

                // Set flags
                if y > y_neg {
                    result[0] += Y_SIGN_FLAG;
                }
                result[0] += COMPRESSION_FLAG;

                result
            };
            assert_eq!(point, bls12_381_g1_decompress(&compressed_point));

            // Double the point to create a "random" point for the next iteration.
            point = point.clone().sw_double();
        }
    }

    fn bls_decompress_risc_v_program(w_ptr: u32, compressed: &[u8]) -> Program {
        assert_eq!(compressed.len(), 48);

        let mut instructions = vec![];

        let mut words = bytes_to_words_be_vec([compressed, &[0u8; 48]].concat().as_slice());
        words.reverse();

        for i in 0..words.len() {
            instructions.push(Instruction::new(Opcode::ADD, 29, 0, words[i], false, true));
            instructions.push(Instruction::new(
                Opcode::ADD,
                30,
                0,
                w_ptr + (i as u32) * 4,
                false,
                true,
            ));
            instructions.push(Instruction::new(Opcode::SW, 29, 30, 0, false, true));
        }

        instructions.extend(vec![
            Instruction::new(
                Opcode::ADD,
                5,
                0,
                SyscallCode::BLS12381_G1_DECOMPRESS as u32,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, 10, 0, w_ptr, false, true),
            Instruction::new(Opcode::ADD, 11, 0, 0, false, true),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ]);
        Program::new(instructions, 0, 0)
    }

    const CANDIDATES: [[u8; 48]; 4] = [
        [
            128, 181, 135, 148, 52, 27, 78, 148, 13, 235, 10, 222, 148, 47, 2, 89, 248, 37, 76, 33,
            223, 74, 74, 102, 121, 191, 228, 14, 144, 134, 65, 196, 196, 179, 29, 52, 188, 151,
            130, 217, 19, 140, 56, 237, 23, 143, 187, 17,
        ],
        [
            166, 149, 173, 50, 93, 252, 126, 17, 145, 251, 201, 241, 134, 245, 142, 255, 66, 166,
            52, 2, 151, 49, 177, 131, 128, 255, 137, 191, 66, 196, 100, 164, 44, 184, 202, 85, 178,
            0, 240, 81, 245, 127, 30, 24, 147, 198, 135, 89,
        ],
        [
            179, 44, 55, 73, 219, 90, 162, 144, 118, 142, 170, 188, 197, 226, 44, 223, 102, 32,
            166, 101, 39, 215, 91, 115, 175, 209, 23, 20, 243, 170, 185, 166, 196, 140, 186, 162,
            114, 52, 88, 7, 0, 214, 47, 175, 129, 52, 248, 110,
        ],
        [
            128, 183, 213, 204, 76, 81, 8, 121, 165, 14, 143, 54, 218, 155, 196, 74, 62, 142, 33,
            208, 87, 222, 166, 154, 164, 110, 63, 127, 138, 93, 182, 225, 19, 233, 159, 107, 33,
            26, 109, 200, 54, 243, 158, 202, 205, 126, 190, 5,
        ],
    ];

    #[test]
    fn test_weierstrass_bls_decompress_risc_v_program() {
        utils::setup_logger();

        for compressed_g1 in &CANDIDATES {
            // use bls12_381 crate to compute expected value
            let mut expected = G1Affine::from_compressed(compressed_g1)
                .unwrap()
                .to_uncompressed();
            expected[0] &= 0b_0001_1111;

            let memory_pointer = 100u32;
            let program = bls_decompress_risc_v_program(memory_pointer, compressed_g1.as_ref());
            let (_, memory) = run_test_with_memory_inspection(program);

            let mut decompressed_g1 = vec![];
            // decompressed G1 occupies 96 bytes or 24 words (8 bytes each): 96 / 8 = 24
            for i in 0..24 {
                decompressed_g1.push(memory.get(&(memory_pointer + i * 4)).unwrap().value);
            }

            let mut decompressed_g1 = words_to_bytes_le_vec(&decompressed_g1);
            decompressed_g1.reverse();

            assert_eq!(
                decompressed_g1,
                expected.to_vec(),
                "Failed on {:?}",
                compressed_g1
            );
        }
    }

    #[test]
    fn test_weierstrass_bls12381_g1_decompress() {
        utils::setup_logger();

        let mut rng = StdRng::seed_from_u64(2);

        let point = bls12_381::G1Projective::random(&mut rng);
        let pt_affine = point.to_affine();
        let pt_compressed = pt_affine.to_compressed();
        let pt_uncompressed = pt_affine.to_uncompressed();

        let inputs = SphinxStdin::from(&pt_compressed[..]);

        let mut public_values =
            run_test_io(Program::from(BLS12381_G1_DECOMPRESS_ELF), &inputs).unwrap();
        let mut result = [0; 96];
        public_values.read_slice(&mut result);
        assert_eq!(result, pt_uncompressed);
    }

    #[test]
    fn test_weierstrass_bls12381_g1_decompress_candidates() {
        utils::setup_logger();

        for candidate in &CANDIDATES {
            let pt_compressed = candidate;
            let pt_affine = G1Affine::from_compressed(candidate).unwrap();
            let pt_uncompressed = pt_affine.to_uncompressed();

            let inputs = SphinxStdin::from(&pt_compressed[..]);

            let mut public_values =
                run_test_io(Program::from(BLS12381_G1_DECOMPRESS_ELF), &inputs).unwrap();
            let mut result = [0; 96];
            public_values.read_slice(&mut result);
            assert_eq!(result, pt_uncompressed);
        }
    }

    #[test]
    fn test_weierstrass_bls12381_g1_decompress_infinity_point_elf() {
        utils::setup_logger();

        let compressed = G1Affine::identity().to_compressed();
        let expected = G1Affine::from_compressed(&compressed)
            .unwrap()
            .to_uncompressed();

        let mut public_values = run_test_io(
            Program::from(BLS12381_G1_DECOMPRESS_ELF),
            &SphinxStdin::from(&compressed),
        )
        .unwrap();
        let mut result = [0; 96];
        public_values.read_slice(&mut result);

        assert_eq!(expected, result);
    }
}
