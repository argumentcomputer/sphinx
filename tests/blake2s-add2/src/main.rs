#![no_main]
sphinx_zkvm::entrypoint!(main);

use sphinx_zkvm::syscalls::blake2s_add_2::syscall_blake2s_add_2;

pub fn main() {
    let mut a: [u32; 4] = [200, 300, 400, 500];
    let b: [u32; 12] = [10, 20, 30, 40, 0, 0, 0, 0, 0, 0, 0, 0];

    syscall_blake2s_add_2(a.as_mut_ptr(), b.as_ptr());

    assert_eq!(a, [210, 320, 430, 540]);
}
