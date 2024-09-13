#![no_main]
sphinx_zkvm::entrypoint!(main);

use sphinx_zkvm::syscalls::blake2s_xor_rotate_16::syscall_blake2s_xor_rotate_16;

pub fn main() {
    let mut w = [1u32; 64];
    for _ in 0..10000 {
        syscall_blake2s_xor_rotate_16(w.as_mut_ptr());
    }
}

// summary: cycles=40957, e2e=17694, khz=2.31, proofSize=2.07 MiB
