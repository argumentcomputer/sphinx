#![no_main]
sphinx_zkvm::entrypoint!(main);

use sphinx_zkvm::syscalls::blake2s_round::syscall_blake2s_quarter_round_2x;

pub fn main() {
    let mut a: [u32; 16] = [
        0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
        0xe07c2654, 0x5be0cd19
    ];
    let b: [u32; 24] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    syscall_blake2s_quarter_round_2x(a.as_mut_ptr(), b.as_ptr());

    assert_eq!(a, [
        0x82a01b5d, 0x248bd8f5, 0x1da4b59a, 0xb37b2bd3,
        0x515f5af4, 0x301095b, 0xb151a3c2, 0x5e17f96f,
        0xc561666d, 0xf291605, 0x990c6d13, 0x76fff6f1,
        0x1e53bf19, 0x6fe4a680, 0x8e33663, 0x97fd885e,
    ]);
}
