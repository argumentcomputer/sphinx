pub mod edwards;
pub mod field;
pub mod keccak256;
pub mod quad_field;
pub mod secp256k1;
pub mod sha256;
pub mod weierstrass;

use crate::runtime::SyscallContext;
use crate::utils::ec::{AffinePoint, EllipticCurve};
use crate::{runtime::MemoryReadRecord, runtime::MemoryWriteRecord};

use hybrid_array::{typenum::Unsigned, Array};
use serde::{Deserialize, Serialize};

use crate::{
    operations::field::params::{LimbWidth, DEFAULT_NUM_LIMBS_T, WORDS_CURVEPOINT},
    utils::ec::BaseLimbWidth,
};

/// Elliptic curve add event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECAddEvent<U: LimbWidth = DEFAULT_NUM_LIMBS_T> {
    pub lookup_id: usize,
    pub shard: u32,
    pub channel: u32,
    pub clk: u32,
    pub p_ptr: u32,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub p: Array<u32, WORDS_CURVEPOINT<U>>,
    pub q_ptr: u32,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub q: Array<u32, WORDS_CURVEPOINT<U>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub p_memory_records: Array<MemoryWriteRecord, WORDS_CURVEPOINT<U>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub q_memory_records: Array<MemoryReadRecord, WORDS_CURVEPOINT<U>>,
}

pub fn create_ec_add_event<E: EllipticCurve>(
    rt: &mut SyscallContext<'_>,
    arg1: u32,
    arg2: u32,
) -> ECAddEvent<BaseLimbWidth<E>> {
    let start_clk = rt.clk;
    let p_ptr = arg1;
    assert!(p_ptr % 4 == 0,);
    let q_ptr = arg2;
    assert!(q_ptr % 4 == 0,);

    let words_len = WORDS_CURVEPOINT::<BaseLimbWidth<E>>::USIZE;

    let p: Array<u32, WORDS_CURVEPOINT<BaseLimbWidth<E>>> =
        (&rt.slice_unsafe(p_ptr, words_len)[..]).try_into().unwrap();

    let (q_memory_records_vec, q_vec) = rt.mr_slice(q_ptr, words_len);
    let q_memory_records = (&q_memory_records_vec[..]).try_into().unwrap();
    let q: Array<u32, WORDS_CURVEPOINT<BaseLimbWidth<E>>> = (&q_vec[..]).try_into().unwrap();
    // When we write to p, we want the clk to be incremented because p and q could be the same.
    rt.clk += 1;

    let p_affine = AffinePoint::<E>::from_words_le(&p);
    let q_affine = AffinePoint::<E>::from_words_le(&q);
    let result_affine = p_affine + q_affine;
    let result_words = result_affine.to_words_le();
    let p_memory_records = (&rt.mw_slice(p_ptr, &result_words)[..]).try_into().unwrap();

    println!("ec-add lookup id {:?}", rt.syscall_lookup_id);
    ECAddEvent {
        lookup_id: rt.syscall_lookup_id,
        shard: rt.current_shard(),
        channel: rt.current_channel(),
        clk: start_clk,
        p_ptr,
        p,
        q_ptr,
        q,
        p_memory_records,
        q_memory_records,
    }
}

/// Elliptic curve double event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECDoubleEvent<U: LimbWidth = DEFAULT_NUM_LIMBS_T> {
    pub lookup_id: usize,
    pub shard: u32,
    pub channel: u32,
    pub clk: u32,
    pub p_ptr: u32,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub p: Array<u32, WORDS_CURVEPOINT<U>>,
    #[serde(with = "crate::utils::array_serde::ArraySerde")]
    pub p_memory_records: Array<MemoryWriteRecord, WORDS_CURVEPOINT<U>>,
}

pub fn create_ec_double_event<E: EllipticCurve>(
    rt: &mut SyscallContext<'_>,
    arg1: u32,
    _: u32,
) -> ECDoubleEvent<BaseLimbWidth<E>> {
    let start_clk = rt.clk;
    let p_ptr = arg1;
    assert!(p_ptr % 4 == 0,);

    let words_len = WORDS_CURVEPOINT::<BaseLimbWidth<E>>::USIZE;

    let p: Array<u32, WORDS_CURVEPOINT<BaseLimbWidth<E>>> =
        (&rt.slice_unsafe(p_ptr, words_len)[..]).try_into().unwrap();
    let p_affine = AffinePoint::<E>::from_words_le(&p);
    let result_affine = E::ec_double(&p_affine);
    let result_words = result_affine.to_words_le();
    let p_memory_records = (&rt.mw_slice(p_ptr, &result_words)[..]).try_into().unwrap();

    ECDoubleEvent {
        lookup_id: rt.syscall_lookup_id,
        shard: rt.current_shard(),
        channel: rt.current_channel(),
        clk: start_clk,
        p_ptr,
        p,
        p_memory_records,
    }
}
