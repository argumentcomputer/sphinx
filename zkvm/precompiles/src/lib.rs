//! Precompiles for SP1 zkVM.
//!
//! Specifically, this crate contains user-friendly functions that call SP1 syscalls. Syscalls are
//! also declared here for convenience. In order to avoid duplicate symbol errors, the syscall
//! function impls must live in sp1-zkvm, which is only imported into the end user program crate.
//! In contrast, sp1-precompiles can be imported into any crate in the dependency tree.

pub mod bls12_381;
pub mod bn254;
pub mod io;
pub mod secp256k1;
pub mod unconstrained;
pub mod utils;
#[cfg(feature = "verify")]
pub mod verify;

pub const BIGINT_WIDTH_WORDS: usize = 8;

extern "C" {
    pub fn syscall_halt(exit_code: u8) -> !;
    pub fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize);
    pub fn syscall_read(fd: u32, read_buf: *mut u8, nbytes: usize);
    pub fn syscall_sha256_extend(w: *mut u32);
    pub fn syscall_sha256_compress(w: *mut u32, state: *mut u32);
    pub fn syscall_ed_add(p: *mut u32, q: *mut u32);
    pub fn syscall_ed_decompress(point: &mut [u8; 64]);
    pub fn syscall_secp256k1_add(p: *mut u32, q: *const u32);
    pub fn syscall_secp256k1_double(p: *mut u32);
    pub fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool);
    pub fn syscall_bn254_add(p: *mut u32, q: *const u32);
    pub fn syscall_bn254_double(p: *mut u32);
    pub fn syscall_bls12381_g1_add(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_g1_double(p: *mut u32);
    pub fn syscall_bls12381_g1_decompress(point: &mut [u8; 96]);
    pub fn syscall_keccak_permute(state: *mut u64);
    pub fn syscall_bls12381_fp_add(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_fp_sub(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_fp_mul(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_fp2_add(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_fp2_sub(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_fp2_mul(p: *mut u32, q: *const u32);
    pub fn syscall_enter_unconstrained() -> bool;
    pub fn syscall_exit_unconstrained();
    pub fn syscall_verify_sphinx_proof(vkey: &[u32; 8], pv_digest: &[u8; 32]);
    pub fn syscall_hint_len() -> usize;
    pub fn syscall_hint_read(ptr: *mut u8, len: usize);
    pub fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8;
    pub fn syscall_bls12381_g2_add(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_g2_double(p: *mut u32);
    pub fn syscall_blake2s_xor_rotate_16(w: *mut u32);

    pub fn syscall_blake2s_add_2(left: *mut u32, right: *const u32);
    pub fn syscall_blake2s_add_3(left: *mut u32, right: *const u32);
    pub fn syscall_blake2s_xor_rotate_right_16(left: *mut u32, right: *const u32);
    pub fn syscall_blake2s_xor_rotate_right_12(left: *mut u32, right: *const u32);
    pub fn syscall_blake2s_xor_rotate_right_8(left: *mut u32, right: *const u32);
    pub fn syscall_blake2s_xor_rotate_right_7(left: *mut u32, right: *const u32);
    pub fn syscall_blake2s_quarter_round(left: *mut u32, right: *const u32);
}
