//! Sweeps end-to-end prover performance across a wide range of parameters for Tendermint.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

use itertools::iproduct;
use p3_challenger::CanObserve;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use wp1_core::runtime::Program;
use wp1_core::stark::{Proof, RiscvAir, StarkGenericConfig};
use wp1_core::utils::BabyBearPoseidon2;
use wp1_prover::SP1ProverImpl;

fn main() {
    // Setup tracer.
    let default_filter = "off";
    let log_appender = tracing_appender::rolling::never("scripts/results", "tendermint_sweep.log");
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_filter))
        .add_directive("p3_keccak_air=off".parse().unwrap())
        .add_directive("p3_fri=off".parse().unwrap())
        .add_directive("p3_challenger=off".parse().unwrap())
        .add_directive("p3_dft=off".parse().unwrap())
        .add_directive("sp1_core=off".parse().unwrap());
    tracing_subscriber::fmt::Subscriber::builder()
        .with_ansi(false)
        .with_file(false)
        .with_target(false)
        .with_thread_names(false)
        .with_env_filter(env_filter)
        .with_span_events(FmtSpan::CLOSE)
        .with_writer(log_appender)
        .finish()
        .init();

    // Setup enviroment variables.
    std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

    // Initialize prover.
    let prover = SP1ProverImpl::new();

    // Setup sweep.
    let iterations = [480000u32];
    let shard_sizes = [1 << 19, 1 << 20, 1 << 21, 1 << 22];
    let batch_sizes = [2];
    let elf = include_bytes!(
        "../../examples/tendermint-benchmark/program/elf/riscv32im-succinct-zkvm-elf"
    );

    let mut lines = vec![
        "iterations,shard_size,batch_size,leaf_proving_duration,recursion_proving_duration"
            .to_string(),
    ];
    for (shard_size, iterations, batch_size) in iproduct!(shard_sizes, iterations, batch_sizes) {
        tracing::info!(
            "running: shard_size={}, iterations={}, batch_size={}",
            shard_size,
            iterations,
            batch_size
        );
        std::env::set_var("SHARD_SIZE", shard_size.to_string());

        let stdin = [bincode::serialize::<u32>(&iterations).unwrap()];
        let leaf_proving_start = Instant::now();
        let proof: Proof<BabyBearPoseidon2> = SP1ProverImpl::prove(elf, &stdin);
        let leaf_proving_duration = leaf_proving_start.elapsed().as_secs_f64();

        let wp1_machine = RiscvAir::machine(BabyBearPoseidon2::default());
        let (_, vk) = wp1_machine.setup(&Program::from(elf));
        let mut wp1_challenger = wp1_machine.config().challenger();
        wp1_challenger.observe(vk.commit);
        for shard_proof in proof.shard_proofs.iter() {
            wp1_challenger.observe(shard_proof.commitment.main_commit);
            wp1_challenger.observe_slice(&shard_proof.public_values);
        }

        let recursion_proving_start = Instant::now();
        let _ = prover.reduce_tree(&vk, proof, batch_size);
        let recursion_proving_duration = recursion_proving_start.elapsed().as_secs_f64();

        lines.push(format!(
            "{},{},{},{},{}",
            iterations, shard_size, batch_size, leaf_proving_duration, recursion_proving_duration
        ));
    }

    let file = File::create("scripts/results/tendermint_sweep.csv").unwrap();
    let mut writer = BufWriter::new(file);
    for line in lines.clone() {
        writeln!(writer, "{}", line).unwrap();
    }

    println!("{:#?}", lines);
}
