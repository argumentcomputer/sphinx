#![no_main]
sphinx_zkvm::entrypoint!(main);

extern "C" {
    fn syscall_bls12381_g1_decompress(p: &mut [u8; 96]);
}

pub fn main() {
    let compressed_key: [u8; 48] = sphinx_zkvm::io::read_vec().try_into().unwrap();
    let mut decompressed_key: [u8; 96] = [0u8; 96];

    decompressed_key[..48].copy_from_slice(&compressed_key);

    println!("before: {:?}", decompressed_key);
    unsafe {
        syscall_bls12381_g1_decompress(&mut decompressed_key);
    }
    println!("after: {:?}", decompressed_key);

    sphinx_zkvm::io::commit_slice(&decompressed_key);
}
