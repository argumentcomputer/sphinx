//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sphinx_zkvm::entrypoint!(main);

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let n: u64 = sphinx_zkvm::io::read::<u64>();

    // Write n to public input
    sphinx_zkvm::io::commit(&n);

    // Compute the n'th fibonacci number, using normal Rust code.
    let mut a: u64 = 0;
    let mut b: u64 = 1;
    for _ in 0..n {
        // Naturally overflow at 64 bits
        let c: u64 = a.wrapping_add(b);
        a = b;
        b = c;
    }

    // Write the output of the program.
    //
    // Behind the scenes, this also compiles down to a custom system call which handles writing
    // outputs to the prover.
    sphinx_zkvm::io::commit(&a);
    sphinx_zkvm::io::commit(&b);
}
