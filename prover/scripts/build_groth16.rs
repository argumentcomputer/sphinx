use std::path::PathBuf;

use clap::Parser;
use wp1_core::utils::setup_logger;
use wp1_prover::build::build_groth16_artifacts;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
}

pub fn main() {
    setup_logger();
    let args = Args::parse();
    build_groth16_artifacts(&args.build_dir);
}
