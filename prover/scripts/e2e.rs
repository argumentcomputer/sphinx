use clap::Parser;
use subtle_encoding::hex;
use wp1_core::io::SP1Stdin;
use wp1_prover::SP1Prover;
use wp1_recursion_circuit::stark::build_wrap_circuit;
use wp1_recursion_circuit::witness::Witnessable;
use wp1_recursion_compiler::ir::Witness;
use wp1_recursion_gnark_ffi::{convert, verify, Groth16Prover};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: String,
}

pub fn main() {
    wp1_core::utils::setup_logger();
    std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

    let args = Args::parse();

    let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

    tracing::info!("initializing prover");
    let prover = SP1Prover::new();

    tracing::info!("setup elf");
    let (pk, vk) = prover.setup(elf);

    tracing::info!("prove core");
    let stdin = SP1Stdin::new();
    let core_proof = prover.prove_core(&pk, &stdin);

    tracing::info!("reduce");
    let reduced_proof = prover.reduce(&vk, core_proof, vec![]);

    tracing::info!("compress");
    let compressed_proof = prover.compress(&vk, reduced_proof);

    tracing::info!("wrap");
    let wrapped_proof = prover.wrap_bn254(&vk, compressed_proof);

    tracing::info!("building verifier constraints");
    let constraints = tracing::info_span!("wrap circuit")
        .in_scope(|| build_wrap_circuit(&prover.wrap_vk, &wrapped_proof));

    tracing::info!("building template witness");
    let mut witness = Witness::default();
    wrapped_proof.write(&mut witness);

    tracing::info!("sanity check gnark test");
    Groth16Prover::test(&constraints, witness.clone());

    tracing::info!("sanity check gnark build");
    Groth16Prover::build(&constraints, witness.clone(), args.build_dir.clone().into());

    tracing::info!("sanity check gnark prove");
    let groth16_prover = Groth16Prover::new(args.build_dir.clone().into());

    tracing::info!("gnark prove");
    let proof = groth16_prover.prove(witness.clone());

    tracing::info!("verify gnark proof");
    let verified = verify(&proof, &args.build_dir.clone().into());
    assert!(verified);

    tracing::info!("convert gnark proof");
    let solidity_proof = convert(&proof, &args.build_dir.clone().into());

    // tracing::info!("sanity check plonk bn254 build");
    // PlonkBn254Prover::build(
    //     constraints.clone(),
    //     witness.clone(),
    //     args.build_dir.clone().into(),
    // );

    // tracing::info!("sanity check plonk bn254 prove");
    // let proof = PlonkBn254Prover::prove(witness.clone(), args.build_dir.clone().into());

    println!(
        "{:?}",
        String::from_utf8(hex::encode(proof.encoded_proof)).unwrap()
    );
    println!("solidity proof: {:?}", solidity_proof);
}
