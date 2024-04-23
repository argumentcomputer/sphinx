#![allow(unused)]

use hybrid_array::{sizes::U24, typenum::Unsigned};

use crate::{syscall_bls12381_add, syscall_bls12381_double, utils::CurveOperations};

#[derive(Copy, Clone)]
pub struct Bls12381;

impl CurveOperations<U24> for Bls12381 {
    // The generator has been taken from py_ecc python library by Ethereum Foundation.
    // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/bls12_381/bls12_381_curve.py#L38-L45
    const GENERATOR: [u32; U24::USIZE] = [
        3676489403, 4214943754, 4185529071, 1817569343, 387689560, 2706258495, 2541009157,
        3278408783, 1336519695, 647324556, 832034708, 401724327, 1187375073, 212476713, 2726857444,
        3493644100, 738505709, 14358731, 3587181302, 4243972245, 1948093156, 2694721773,
        3819610353, 146011265,
    ];

    fn add_assign(limbs: &mut [u32; U24::USIZE], other: &[u32; U24::USIZE]) {
        unsafe {
            syscall_bls12381_add(limbs.as_mut_ptr(), other.as_ptr());
        }
    }

    fn double(limbs: &mut [u32; U24::USIZE]) {
        unsafe {
            syscall_bls12381_double(limbs.as_mut_ptr());
        }
    }
}

use crate::syscall_bls12381_g1_decompress;
use anyhow::Result;

/// Decompresses a compressed public key using bls12381_g1_decompress precompile.
pub fn decompress_pubkey(compressed_key: &[u8; 48]) -> Result<[u8; 96]> {
    cfg_if::cfg_if! {
        if #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))] {
            let mut decompressed_key = [0u8; 96];
            decompressed_key[..48].copy_from_slice(compressed_key);
            unsafe {
                syscall_bls12381_g1_decompress(&mut decompressed_key);
            }

            Ok(decompressed_key)
        } else {
            let point = bls12_381::G1Affine::from_compressed(compressed_key).unwrap();
            let mut result = point.to_uncompressed();
            // Note: bls12_381 here produces the uncompressed serialization format
            // which will light the infinity bit on the point at infinity:
            // compressed_key[0] >> 6 |= 1.
            // This is handled out-of-circuit in the zkvm case, inside the `syscall_bls12381_g1_decompress`
            // function, which sets the corresponding bit flag in the return value.
            // In-circuit, for non-infinity points, the output is a simple X, Y point array with none of the
            // bits set.
            // Thus we can just return the bls12_381 return value as-is since it is equivalent.
            Ok(result)
        }
    }
}
