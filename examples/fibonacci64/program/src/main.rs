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

    let result = fib(n);

    // Write the output of the program.
    //
    // Behind the scenes, this also compiles down to a custom system call which handles writing
    // outputs to the prover.
    sphinx_zkvm::io::commit(&result);
    sphinx_zkvm::io::commit(&result);
}

// [0, 1, 2, 3] = |0 1|
//                |2 3|
type Matrix2x2 = [u64; 4];

fn matmul(a: Matrix2x2, b: Matrix2x2) -> Matrix2x2 {
    [
        a[0] * b[0] + a[1] * b[2],
        a[0] * b[1] + a[1] * b[3],
        a[1] * b[0] + a[3] * b[2],
        a[2] * b[1] + a[3] * b[3],
    ]
}

fn fast_matexp(b: Matrix2x2, e: u64) -> Matrix2x2 {
    if e == 0 {
        [1, 0, 0, 1] // identity matrix
    } else {
        if e % 2 == 1 {
            // odd?
            matmul(b, fast_matexp(matmul(b, b), (e - 1) / 2))
        } else {
            fast_matexp(matmul(b, b), e / 2)
        }
    }
}

fn fib(n: u64) -> u64 {
    fast_matexp([0, 1, 1, 1], n + 1)[0]
}
