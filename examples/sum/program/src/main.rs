//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input = sp1_zkvm::io::read::<Vec<u64>>();

    let output = input.iter().fold(0, |acc, i| acc + i);

    sp1_zkvm::io::commit(&input);
    sp1_zkvm::io::commit(&output);
}
