//! A simple program to be proven inside the zkVM.

#![no_main]
sphinx_zkvm::entrypoint!(main);

pub fn main() {
    let input = sphinx_zkvm::io::read::<Vec<u64>>();

    let output: u64 = input.iter().sum();

    sphinx_zkvm::io::commit(&input);
    sphinx_zkvm::io::commit(&output);
}
