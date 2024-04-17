#![no_main]
wp1_zkvm::entrypoint!(main);

extern "C" {
    fn syscall_bls12381_decompress(p: &mut [u8; 96], is_odd: bool);
}

pub fn main() {
    // Call precompile 3 times just at different inputto ensure that e2e proving works with the underlying chip invoked multiple times

    // successful if running decompression case via `run_test` directly in unit-test
    let compressed_g1: [u8; 48] = [166, 149, 173, 50, 93, 252, 126, 17, 145, 251, 201, 241, 134, 245, 142, 255, 66, 166, 52, 2, 151, 49, 177, 131, 128, 255, 137, 191, 66, 196, 100, 164, 44, 184, 202, 85, 178, 0, 240, 81, 245, 127, 30, 24, 147, 198, 135, 89];
    let mut decompressed_g1: [u8; 96] = [0u8; 96];

    decompressed_g1[..48].copy_from_slice(&compressed_g1);

    let is_odd = (decompressed_g1[0] & 0b_0010_0000) >> 5 == 0;
    decompressed_g1[0] &= 0b_0001_1111;


    unsafe {
        syscall_bls12381_decompress(&mut decompressed_g1, is_odd);
    }

    let expected: [u8; 96] = [6, 149, 173, 50, 93, 252, 126, 17, 145, 251, 201, 241, 134, 245, 142, 255, 66, 166, 52, 2, 151, 49, 177, 131, 128, 255, 137, 191, 66, 196, 100, 164, 44, 184, 202, 85, 178, 0, 240, 81, 245, 127, 30, 24, 147, 198, 135, 89, 16, 234, 121, 18, 239, 122, 34, 124, 1, 41, 138, 124, 122, 150, 177, 133, 27, 35, 2, 23, 65, 199, 25, 56, 243, 150, 56, 177, 211, 104, 170, 166, 33, 69, 36, 38, 181, 216, 25, 151, 115, 162, 203, 91, 39, 67, 165, 218];
    assert_eq!(decompressed_g1, expected);


    // fails if running decompression case via `run_test` directly in unit-test
    let compressed_g1: [u8; 48] = [179, 44, 55, 73, 219, 90, 162, 144, 118, 142, 170, 188, 197, 226, 44, 223, 102, 32, 166, 101, 39, 215, 91, 115, 175, 209, 23, 20, 243, 170, 185, 166, 196, 140, 186, 162, 114, 52, 88, 7, 0, 214, 47, 175, 129, 52, 248, 110];
    let mut decompressed_g1: [u8; 96] = [0u8; 96];

    decompressed_g1[..48].copy_from_slice(&compressed_g1);

    let is_odd = (decompressed_g1[0] & 0b_0010_0000) >> 5 == 0;
    decompressed_g1[0] &= 0b_0001_1111;
    unsafe {
        syscall_bls12381_decompress(&mut decompressed_g1, is_odd);
    }
    let expected: [u8; 96] = [19, 44, 55, 73, 219, 90, 162, 144, 118, 142, 170, 188, 197, 226, 44, 223, 102, 32, 166, 101, 39, 215, 91, 115, 175, 209, 23, 20, 243, 170, 185, 166, 196, 140, 186, 162, 114, 52, 88, 7, 0, 214, 47, 175, 129, 52, 248, 110, 16, 137, 199, 235, 30, 181, 250, 15, 195, 103, 24, 141, 240, 97, 40, 190, 4, 103, 139, 194, 3, 25, 72, 94, 164, 126, 142, 39, 78, 17, 188, 35, 141, 251, 204, 57, 113, 55, 176, 219, 28, 9, 199, 235, 97, 205, 99, 197];
    assert_eq!(decompressed_g1, expected);

    // fails if running decompression case via `run_test` directly in unit-test
    let compressed_g1: [u8; 48] = [128, 183, 213, 204, 76, 81, 8, 121, 165, 14, 143, 54, 218, 155, 196, 74, 62, 142, 33, 208, 87, 222, 166, 154, 164, 110, 63, 127, 138, 93, 182, 225, 19, 233, 159, 107, 33, 26, 109, 200, 54, 243, 158, 202, 205, 126, 190, 5];
    let mut decompressed_g1: [u8; 96] = [0u8; 96];

    decompressed_g1[..48].copy_from_slice(&compressed_g1);

    let is_odd = (decompressed_g1[0] & 0b_0010_0000) >> 5 == 0;
    decompressed_g1[0] &= 0b_0001_1111;
    unsafe {
        syscall_bls12381_decompress(&mut decompressed_g1, is_odd);
    }
    let expected: [u8; 96] = [0, 183, 213, 204, 76, 81, 8, 121, 165, 14, 143, 54, 218, 155, 196, 74, 62, 142, 33, 208, 87, 222, 166, 154, 164, 110, 63, 127, 138, 93, 182, 225, 19, 233, 159, 107, 33, 26, 109, 200, 54, 243, 158, 202, 205, 126, 190, 5, 11, 154, 179, 161, 111, 71, 197, 147, 145, 192, 191, 229, 26, 185, 105, 210, 204, 253, 109, 191, 184, 30, 223, 144, 57, 99, 86, 225, 106, 133, 83, 44, 110, 201, 136, 90, 22, 4, 72, 69, 120, 208, 178, 220, 117, 20, 190, 54];
    assert_eq!(decompressed_g1, expected);
}
