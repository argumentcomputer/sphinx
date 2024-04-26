//! Sweeps end-to-end prover performance across a wide range of parameters for Fibonacci.
use std::fs::File;
use std::io::{BufWriter, Write};

use itertools::iproduct;
use wp1_core::utils::{inner_perm, InnerChallenge, InnerVal};
use wp1_recursion_core::runtime::Runtime;
use wp1_recursion_program::fri::two_adic_pcs::tests::build_test_fri_with_cols_and_log2_rows;

fn main() {
    // Setup sweep.
    let columns = [10, 50, 100, 200, 400];
    let log2_rows = [18, 19, 20, 21, 22, 23];

    let mut lines = vec!["columns,log2_rows,cycles".to_string()];
    for (columns, log2_rows) in iproduct!(columns, log2_rows) {
        println!("running: columns={}, log2_rows={}", columns, log2_rows);
        let (program, witness) = build_test_fri_with_cols_and_log2_rows(columns, log2_rows);
        let mut runtime = Runtime::<InnerVal, InnerChallenge, _>::new(&program, inner_perm());
        runtime.witness_stream = witness;
        runtime.run();
        lines.push(format!("{},{},{}", columns, log2_rows, runtime.timestamp));
    }

    let file = File::create("results/fri_sweep.csv").unwrap();
    let mut writer = BufWriter::new(file);
    for line in lines.clone() {
        writeln!(writer, "{}", line).unwrap();
    }

    println!("{:#?}", lines);
}
