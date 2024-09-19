#![no_main]
sphinx_zkvm::entrypoint!(main);

use sphinx_zkvm::syscalls::blake2s_quarter_round_2x::syscall_blake2s_quarter_round_2x;

pub fn main() {
    let mut a: [u32; 16] = [
        0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
        0xe07c2654, 0x5be0cd19
    ];
    let b: [u32; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    syscall_blake2s_quarter_round_2x(a.as_mut_ptr(), b.as_ptr());

    assert_eq!(a, [
        0xdc0f959e, 0x8c871712, 0xc6a650d4, 0xd26fb9fc, 0x408705aa, 0x8d07c52d, 0xb9d6aa3a,
        0x88609304, 0x5c7a89f8, 0xb5f896c7, 0x81e69eeb, 0xe17775ed, 0x87b6b678, 0x7af31ada,
        0x5a2defeb, 0x2cdd25e3,
    ]);

    /*
    assert_eq!(a, [
        0xdc0f959e, 0x8c871712, 0xc6a650d4, 0xd26fb9fc,
        0x8d07c52d, 0xb9d6aa3a, 0x88609304, 0x408705aa,
        0x81e69eeb, 0xe17775ed, 0x5c7a89f8, 0xb5f896c7,
        0x2cdd25e3, 0x87b6b678, 0x7af31ada, 0x5a2defeb
    ]);*/
}
