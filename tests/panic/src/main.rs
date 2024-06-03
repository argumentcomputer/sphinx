#![no_main]
sphinx_zkvm::entrypoint!(main);

pub fn main() {
    assert_eq!(0, 1);
}
