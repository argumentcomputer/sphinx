//! A simple program that takes two strings and computes their longest common subsequence as output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sphinx_zkvm::entrypoint!(main);

use std::cmp::max;
use std::collections::VecDeque;

fn lcs_dyn(xs: &str, ys: &str) -> String {
    let xs: Vec<char> = xs.chars().collect();
    let ys: Vec<char> = ys.chars().collect();
    let (m, n) = (xs.len(), ys.len());

    let mut tab: Vec<VecDeque<i32>> = vec![VecDeque::from(vec![0; n + 1]); m + 1];

    for (i, &x) in xs.iter().enumerate() {
        let mut row = VecDeque::from(vec![0]);
        for (j, &y) in ys.iter().enumerate() {
            let val = if x == y {
                1 + tab[i][j]
            } else {
                max(tab[i][j + 1], row[j])
            };
            row.push_back(val);
        }
        tab[i + 1] = row;
    }

    construct(&xs, &ys, &tab)
}

fn construct(xs: &[char], ys: &[char], tab: &[VecDeque<i32>]) -> String {
    let mut result = Vec::new();
    let (mut i, mut j) = (xs.len(), ys.len());

    while i > 0 && j > 0 {
        if xs[i - 1] == ys[j - 1] {
            result.push(xs[i - 1]);
            i -= 1;
            j -= 1;
        } else if tab[i - 1][j] > tab[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }

    result.reverse();
    result.into_iter().collect()
}

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let input = sphinx_zkvm::io::read::<(String, String)>();

    // Write input to public input
    sphinx_zkvm::io::commit(&input);

    let lcs = lcs_dyn(&input.0, &input.1);

    // Write the output of the program.
    //
    // Behind the scenes, this also compiles down to a custom system call which handles writing
    // outputs to the prover.
    sphinx_zkvm::io::commit(&lcs);
}
