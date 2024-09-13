#![no_main]
sphinx_zkvm::entrypoint!(main);

use sphinx_zkvm::syscalls::blake2s_xor_rotate_right::syscall_blake2s_xor_rotate_right;

pub fn main() {
    let mut a: [u32; 4] = [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a];
    let b: [u32; 4] = [0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

    syscall_blake2s_xor_rotate_right(a.as_mut_ptr(), b.as_ptr());

    assert_eq!(a, [0xb4383a06, 0xc6092062, 0x2ad923ed, 0x3823feaf]);

    // precompile code
    //for _ in 0..10000 {
    //    syscall_blake2s_xor_rotate_right(a.as_mut_ptr(), b.as_ptr());
    //}

    // no-precompile code
    //for _ in 0..10000 {
    //    for i in 0..4usize {
    //        a[i] = (a[i] ^ b[i]).rotate_right(b[4]);
    //    }
    //}
}


// summary: cycles=61049, e2e=3532, khz=17.28, proofSize=1.84 MiB (precompile)
// summary: cycles=1044, e2e=1691, khz=0.62, proofSize=1.84 MiB (no precompile)