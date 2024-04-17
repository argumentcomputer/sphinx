#![no_main]
wp1_zkvm::entrypoint!(main);

extern "C" {
    fn syscall_bls12381_decompress(p: &mut [u8; 96], is_odd: bool);
}

pub fn main() {
    let compressed_g1: [u8; 48] = [166, 149, 173, 50, 93, 252, 126, 17, 145, 251, 201, 241, 134, 245, 142, 255, 66, 166, 52, 2, 151, 49, 177, 131, 128, 255, 137, 191, 66, 196, 100, 164, 44, 184, 202, 85, 178, 0, 240, 81, 245, 127, 30, 24, 147, 198, 135, 89];
    let mut decompressed_g1: [u8; 96] = [0u8; 96];

    decompressed_g1[..48].copy_from_slice(&compressed_g1);

    let is_odd = (decompressed_g1[0] & 0b_0010_0000) >> 5 == 0;
    decompressed_g1[0] &= 0b_0001_1111;

    // Call precompile multiple times just to ensure that e2e proving works with the underlying chip invoked multiple times
    unsafe {
        syscall_bls12381_decompress(&mut decompressed_g1, is_odd);
    }
    unsafe {
        syscall_bls12381_decompress(&mut decompressed_g1, is_odd);
    }
    unsafe {
        syscall_bls12381_decompress(&mut decompressed_g1, is_odd);
    }

    let expected: [u8; 96] = [6, 149, 173, 50, 93, 252, 126, 17, 145, 251, 201, 241, 134, 245, 142, 255, 66, 166, 52, 2, 151, 49, 177, 131, 128, 255, 137, 191, 66, 196, 100, 164, 44, 184, 202, 85, 178, 0, 240, 81, 245, 127, 30, 24, 147, 198, 135, 89, 16, 234, 121, 18, 239, 122, 34, 124, 1, 41, 138, 124, 122, 150, 177, 133, 27, 35, 2, 23, 65, 199, 25, 56, 243, 150, 56, 177, 211, 104, 170, 166, 33, 69, 36, 38, 181, 216, 25, 151, 115, 162, 203, 91, 39, 67, 165, 218];
    assert_eq!(decompressed_g1, expected);
}
