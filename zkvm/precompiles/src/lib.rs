pub mod bls12_381;
pub mod bn254;
pub mod io;
pub mod secp256k1;
pub mod unconstrained;
pub mod utils;
#[cfg(feature = "verify")]
pub mod verify;

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
    pub fn syscall_blake3_compress_inner(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_fp_add(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_fp_sub(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_fp_mul(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_fp2_add(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_fp2_sub(p: *mut u32, q: *const u32);
    pub fn syscall_bls12381_fp2_mul(p: *mut u32, q: *const u32);
    pub fn syscall_enter_unconstrained() -> bool;
    pub fn syscall_exit_unconstrained();
    pub fn syscall_verify_wp1_proof(vkey: &[u32; 8], pv_digest: &[u8; 32]);
    pub fn syscall_hint_len() -> usize;
    pub fn syscall_hint_read(ptr: *mut u8, len: usize);
    pub fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8;
    pub fn syscall_bls12381_g2_add(p: *mut u32, q: *const u32);
}
