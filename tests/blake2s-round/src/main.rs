#![no_main]
sphinx_zkvm::entrypoint!(main);

use sphinx_zkvm::syscalls::blake2s_round::syscall_blake2s_round;

pub fn main() {
    let mut a: [u32; 16] = [
        0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
        0xe07c2654, 0x5be0cd19
    ];
    let b: [u32; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    syscall_blake2s_round(a.as_mut_ptr(), b.as_ptr());
}
