#![no_main]
sphinx_zkvm::entrypoint!(main);

extern "C" {
    fn syscall_bls12381_fp_sub(p: *mut u32, q: *const u32);
}

pub fn main() {
    let a: [u8; 48] = [
        228, 106, 72, 120, 77, 201, 20, 66, 102, 164, 169, 130, 27, 165, 141, 9, 68, 102, 5, 170,
        209, 70, 36, 126, 113, 18, 24, 91, 5, 80, 169, 75, 130, 40, 70, 1, 62, 71, 120, 57, 209,
        104, 210, 238, 188, 198, 117, 7,
    ];
    let b: [u8; 48] = [
        96, 73, 110, 78, 155, 199, 140, 30, 164, 39, 135, 40, 82, 215, 126, 255, 139, 203, 67, 42,
        199, 165, 207, 109, 234, 238, 119, 155, 55, 29, 171, 109, 95, 128, 76, 12, 116, 155, 167,
        88, 28, 196, 19, 0, 90, 60, 100, 17,
    ];
    let sub: [u8; 48] = [
        47, 204, 217, 41, 178, 1, 135, 221, 193, 124, 118, 11, 200, 205, 186, 40, 220, 144, 114,
        118, 171, 115, 133, 119, 70, 54, 37, 179, 82, 126, 117, 66, 250, 84, 69, 56, 128, 83, 236,
        43, 79, 139, 62, 40, 77, 156, 18, 16,
    ];

    let mut out = a.clone();
    unsafe {
        syscall_bls12381_fp_sub(out.as_mut_ptr() as *mut u32, b.as_ptr() as *const u32);
    }
    assert_eq!(out, sub);

    println!("done");
}
