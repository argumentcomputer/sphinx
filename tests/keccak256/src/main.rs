#![no_main]
sphinx_zkvm::entrypoint!(main);

use tiny_keccak::{Hasher, Keccak};

pub fn main() {
    let num_cases = sphinx_zkvm::io::read::<usize>();
    for _ in 0..num_cases {
        let input = sphinx_zkvm::io::read::<Vec<u8>>();
        let mut hasher = Keccak::v256();
        hasher.update(&input);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        sphinx_zkvm::io::commit(&output);
    }
}
