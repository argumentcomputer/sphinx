#![no_main]
sphinx_zkvm::entrypoint!(main);

use sphinx_zkvm::syscalls::blake2s_xor_rotate_right_7::syscall_blake2s_xor_rotate_right_7;

pub fn main() {
    let mut a: [u32; 4] = [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a];
    let b: [u32; 4] = [0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

    syscall_blake2s_xor_rotate_right_7(a.as_mut_ptr(), b.as_ptr());

    assert_eq!(a, [0x70740d68, 0x1240c58c, 0xb247da55, 0x47fd5e70]);
}
