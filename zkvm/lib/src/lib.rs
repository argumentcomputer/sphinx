//! System calls for the SP1 zkVM.
pub mod bls12_381;
pub mod bn254;
pub mod io;
#[cfg(feature = "secp256k1")]
pub mod secp256k1;
pub mod unconstrained;
pub mod utils;
#[cfg(feature = "verify")]
pub mod verify;

extern "C" {
    /// Halts the program with the given exit code.
    pub fn syscall_halt(exit_code: u8) -> !;

    /// Writes the bytes in the given buffer to the given file descriptor.
    pub fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize);

    /// Reads the bytes from the given file descriptor into the given buffer.
    pub fn syscall_read(fd: u32, read_buf: *mut u8, nbytes: usize);

    /// Executes the SHA-256 extend operation on the given word array.
    pub fn syscall_sha256_extend(w: *mut u32);

    /// Executes the SHA-256 compress operation on the given word array and a given state.
    pub fn syscall_sha256_compress(w: *mut u32, state: *mut u32);
    pub fn syscall_sha512_extend(w: *mut u64, i: u32);
    pub fn syscall_sha512_compress(w: *mut u64, state: *mut u64);

    /// Executes an Ed25519 curve addition on the given points.
    pub fn syscall_ed_add(p: *mut u32, q: *mut u32);

    /// Executes an Ed25519 curve decompression on the given point.
    pub fn syscall_ed_decompress(point: &mut [u8; 64]);

    /// Executes an Sepc256k1 curve addition on the given points.
    pub fn syscall_secp256k1_add(p: *mut u32, q: *const u32);

    /// Executes an Secp256k1 curve doubling on the given point.
    pub fn syscall_secp256k1_double(p: *mut u32);

    /// Executes an Secp256k1 curve decompression on the given point.
    pub fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool);

    /// Executes a Bn254 curve addition on the given points.
    pub fn syscall_bn254_add(p: *mut u32, q: *const u32);

    /// Executes a Bn254 curve doubling on the given point.
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

    /// Exits unconstrained mode.
    pub fn syscall_exit_unconstrained();
    pub fn syscall_verify_sphinx_proof(vkey: &[u32; 8], pv_digest: &[u8; 32]);
    pub fn syscall_hint_len() -> usize;

    /// Reads the next element in the hint stream into the given buffer.
    pub fn syscall_hint_read(ptr: *mut u8, len: usize);

    /// Allocates a buffer aligned to the given alignment.
    pub fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8;
    pub fn syscall_blake2s_round(left: *mut u32, right: *const u32);
}
