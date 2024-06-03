#![no_main]
sphinx_zkvm::entrypoint!(main);

extern "C" {
    fn syscall_bls12381_fp2_add(p: *mut u32, q: *const u32);
}

pub fn main() {
    let a: [u8; 96] = [
        137, 214, 20, 51, 154, 5, 119, 78, 103, 112, 15, 10, 160, 81, 219, 107, 10, 97, 141, 56,
        183, 221, 124, 243, 118, 41, 236, 122, 149, 40, 29, 6, 119, 244, 21, 26, 40, 203, 20, 28,
        8, 39, 167, 1, 125, 45, 134, 18, 98, 253, 223, 82, 158, 161, 179, 84, 30, 122, 142, 227,
        46, 167, 60, 30, 129, 1, 79, 174, 115, 21, 175, 43, 2, 206, 23, 252, 188, 97, 51, 163, 2,
        236, 163, 189, 114, 56, 183, 105, 10, 193, 201, 137, 107, 55, 152, 22,
    ];
    let b: [u8; 96] = [
        32, 226, 105, 47, 227, 133, 211, 239, 149, 35, 250, 248, 46, 146, 20, 143, 195, 201, 170,
        108, 195, 100, 248, 55, 45, 167, 243, 50, 253, 214, 24, 100, 88, 92, 45, 128, 153, 168, 99,
        203, 98, 55, 228, 148, 210, 50, 87, 22, 112, 255, 46, 135, 164, 189, 141, 245, 248, 44,
        117, 120, 42, 57, 123, 53, 117, 50, 167, 211, 70, 151, 85, 56, 214, 199, 47, 194, 141, 15,
        17, 153, 151, 37, 100, 62, 56, 114, 54, 82, 102, 182, 224, 32, 165, 225, 91, 20,
    ];
    let add: [u8; 96] = [
        254, 13, 127, 98, 125, 139, 75, 132, 253, 147, 181, 81, 208, 227, 67, 220, 169, 52, 135,
        174, 217, 111, 68, 196, 228, 189, 90, 186, 13, 180, 190, 5, 248, 163, 247, 86, 11, 204, 92,
        156, 208, 119, 11, 93, 101, 78, 220, 14, 39, 82, 15, 218, 66, 95, 66, 144, 23, 167, 175,
        170, 90, 224, 11, 53, 210, 61, 69, 139, 25, 218, 211, 252, 24, 131, 194, 202, 197, 37, 205,
        215, 194, 100, 188, 184, 244, 2, 210, 112, 214, 144, 42, 113, 38, 7, 243, 16,
    ];

    let mut out = a.clone();
    unsafe {
        syscall_bls12381_fp2_add(out.as_mut_ptr() as *mut u32, b.as_ptr() as *const u32);
    }
    assert_eq!(out, add);

    println!("done");
}
