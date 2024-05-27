#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Adds two Bls12381 points.
///
/// The result is stored in the first point.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_g1_add(p: *mut u32, q: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLS12381_G1_ADD,
            in("a0") p,
            in("a1") q,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Double a Bls12381 point.
///
/// The result is stored in the first point.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_g1_double(p: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLS12381_G1_DOUBLE,
            in("a0") p,
            in("a1") 0,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Adds two G2Affine Bls12381 points.
///
/// The result is stored in the first point.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_g2_add(p: *mut u32, q: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
        "ecall",
        in("t0") crate::syscalls::BLS12381_G2_ADD,
        in("a0") p,
        in("a1") q,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Doubles two G2Affine Bls12381 points.
///
/// The result is stored in the first point.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_g2_double(p: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
        "ecall",
        in("t0") crate::syscalls::BLS12381_G2_DOUBLE,
        in("a0") p,
        in("a1") 0,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Adds two BLS12381 Fp field elements
///
/// The result is stored by overwriting the first argument.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_fp_add(p: *mut u32, q: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLS12381_FP_ADD,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_fp_sub(p: *mut u32, q: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLS12381_FP_SUB,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_fp_mul(p: *mut u32, q: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLS12381_FP_MUL,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_fp2_add(p: *mut u32, q: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLS12381_FP2_ADD,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_fp2_sub(p: *mut u32, q: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLS12381_FP2_SUB,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_fp2_mul(p: *mut u32, q: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLS12381_FP2_MUL,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Decompresses a compressed BLS12-381 G1 point.
///
/// The first half of the input array should contain the X coordinate.
/// The second half of the input array will be overwritten with the Y coordinate.
/// The most-significant byte of X will be overwritten to clear any compression flags.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_g1_decompress(point: &mut [u8; 96]) {
    #[cfg(target_os = "zkvm")]
    {
        let compressed_flag = (point[0] >> 7) & 1;
        assert_eq!(compressed_flag, 1);
        let infinity_flag = (point[0] >> 6) & 1;
        // The y_sign_flag is handled in-circuit

        // Handle infinity point case out of circuit for constraint simplicity.
        if infinity_flag != 0 {
            // Check that all other values are zero
            assert_eq!(point[0], (1 << 6) | (1 << 7)); // MSByte has compression and infinity flags set
            for i in 1..96 {
                assert_eq!(point[i], 0);
            }
            // Our point is infinite point, so skipping the precompile invocation and return expected value
            // of uncompressed infinite point, which is array of zeroes with zero element set to 1 << 6.
            point[0] = 1 << 6;
        } else {
            // Memory system/FpOps are little endian so we'll just flip the whole array before/after
            point.reverse();
            let p = point.as_mut_ptr();
            unsafe {
                asm!(
                    "ecall",
                    in("t0") crate::syscalls::BLS12381_G1_DECOMPRESS,
                    in("a0") p,
                    in("a1") 0,
                );
            }
            point.reverse();
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
