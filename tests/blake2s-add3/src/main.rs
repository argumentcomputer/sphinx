#![no_main]
sphinx_zkvm::entrypoint!(main);

use sphinx_zkvm::syscalls::blake2s_add_3::syscall_blake2s_add_3;

pub fn main() {
    let mut a: [u32; 4] = [200, 300, 400, 500];
    let b: [u32; 12] = [10, 20, 30, 40, 1, 2, 3, 4, 0, 0, 0, 0];

    syscall_blake2s_add_3(a.as_mut_ptr(), b.as_ptr());

    assert_eq!(a, [211, 322, 433, 544]);
}
