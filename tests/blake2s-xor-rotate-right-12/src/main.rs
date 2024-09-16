#![no_main]
sphinx_zkvm::entrypoint!(main);

use sphinx_zkvm::syscalls::blake2s_xor_rotate_right_12::syscall_blake2s_xor_rotate_right_12;

pub fn main() {
    let mut a: [u32; 4] = [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a];
    let b: [u32; 4] = [0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

    syscall_blake2s_xor_rotate_right_12(a.as_mut_ptr(), b.as_ptr());

    assert_eq!(a, [0x4383a06b, 0x6092062c, 0xad923ed2, 0x823feaf3]);
}
