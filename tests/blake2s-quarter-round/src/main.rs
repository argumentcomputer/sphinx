#![no_main]
sphinx_zkvm::entrypoint!(main);

use sphinx_zkvm::syscalls::blake2s_quarter_round::syscall_blake2s_quarter_round;

pub fn main() {
    let mut a: [u32; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let b: [u32; 16] = [10, 20, 30, 40, 10, 20, 30, 40, 0, 0, 0, 0, 0, 0, 0, 0];

    syscall_blake2s_quarter_round(a.as_mut_ptr(), b.as_ptr());

    assert_eq!(a, [0x10, 0x1c, 0x28, 0x34, 0xc00000, 0xc00000, 0xc00000, 0x400000, 0x16, 0x18, 0x1a, 0x1c, 0xc0000, 0xc0000, 0xc0000, 0x140000]);
}
