use std::borrow::Borrow;
use std::path::PathBuf;

use p3_baby_bear::BabyBear;
use sphinx_core::stark::StarkVerifyingKey;
use sphinx_core::{io::SphinxStdin, stark::ShardProof};
pub use sphinx_recursion_circuit::stark::build_wrap_circuit;
pub use sphinx_recursion_circuit::witness::Witnessable;
pub use sphinx_recursion_compiler::ir::Witness;
use sphinx_recursion_compiler::{config::OuterConfig, constraints::Constraint};
use sphinx_recursion_core::air::RecursionPublicValues;
pub use sphinx_recursion_core::stark::utils::sphinx_dev_mode;
use sphinx_recursion_gnark_ffi::PlonkBn254Prover;

use crate::install::install_plonk_bn254_artifacts;
use crate::utils::{babybear_bytes_to_bn254, babybears_to_bn254, words_to_bytes};
use crate::{OuterSC, SphinxProver, SP1_CIRCUIT_VERSION};

/// Tries to install the PLONK artifacts if they are not already installed.
pub fn try_install_plonk_bn254_artifacts(use_aws_cli: bool) -> PathBuf {
    let build_dir = plonk_bn254_artifacts_dir();

    if build_dir.exists() {
        println!(
            "[sp1] plonk bn254 artifacts already seem to exist at {}. if you want to re-download them, delete the directory",
            build_dir.display()
        );
    } else {
        println!(
            "[sp1] plonk bn254 artifacts for version {} do not exist at {}. downloading...",
            SP1_CIRCUIT_VERSION,
            build_dir.display()
        );
        install_plonk_bn254_artifacts(&build_dir, use_aws_cli);
    }
    build_dir
}

/// Tries to build the PLONK artifacts inside the development directory.
pub fn try_build_plonk_bn254_artifacts_dev(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
) -> PathBuf {
    let build_dir = plonk_bn254_artifacts_dev_dir();
    println!("[sp1] building plonk bn254 artifacts in development mode");
    build_plonk_bn254_artifacts(template_vk, template_proof, &build_dir);
    build_dir
}

/// Gets the directory where the PLONK artifacts are installed.
fn plonk_bn254_artifacts_dir() -> PathBuf {
    home::home_dir()
        .unwrap()
        .join(".sp1")
        .join("circuits")
        .join("plonk_bn254")
        .join(SP1_CIRCUIT_VERSION)
}

/// Gets the directory where the PLONK artifacts are installed in development mode.
pub fn plonk_bn254_artifacts_dev_dir() -> PathBuf {
    home::home_dir()
        .unwrap()
        .join(".sp1")
        .join("circuits")
        .join("plonk_bn254")
        .join("dev")
}

/// Build the plonk bn254 artifacts to the given directory for the given verification key and template
/// proof.
pub fn build_plonk_bn254_artifacts(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
    build_dir: impl Into<PathBuf>,
) {
    let build_dir = build_dir.into();
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof);
    PlonkBn254Prover::build(&constraints, witness, &build_dir);
}

/// Builds the plonk bn254 artifacts to the given directory.
///
/// This may take a while as it needs to first generate a dummy proof and then it needs to compile
/// the circuit.
pub fn build_plonk_bn254_artifacts_with_dummy(build_dir: impl Into<PathBuf>) {
    let (wrap_vk, wrapped_proof) = dummy_proof();
    build_plonk_bn254_artifacts(&wrap_vk, &wrapped_proof, build_dir.into());
}

/// Build the verifier constraints and template witness for the circuit.
pub fn build_constraints_and_witness(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
) -> (Vec<Constraint>, Witness<OuterConfig>) {
    tracing::info!("building verifier constraints");
    let constraints = tracing::info_span!("wrap circuit")
        .in_scope(|| build_wrap_circuit(template_vk, template_proof));

    let pv: &RecursionPublicValues<BabyBear> = template_proof.public_values.as_slice().borrow();
    let vkey_hash = babybears_to_bn254(&pv.sphinx_vk_digest);
    let committed_values_digest_bytes: [BabyBear; 32] = words_to_bytes(&pv.committed_value_digest)
        .try_into()
        .unwrap();
    let committed_values_digest = babybear_bytes_to_bn254(&committed_values_digest_bytes);

    tracing::info!("building template witness");
    let mut witness = Witness::default();
    template_proof.write(&mut witness);
    witness.write_commited_values_digest(committed_values_digest);
    witness.write_vkey_hash(vkey_hash);

    (constraints, witness)
}

/// Generate a dummy proof that we can use to build the circuit. We need this to know the shape of
/// the proof.
pub fn dummy_proof() -> (StarkVerifyingKey<OuterSC>, ShardProof<OuterSC>) {
    let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

    tracing::info!("initializing prover");
    let prover = SphinxProver::new();

    tracing::info!("setup elf");
    let (pk, vk) = prover.setup(elf);

    tracing::info!("prove core");
    let mut stdin = SphinxStdin::new();
    stdin.write(&500u32);
    let core_proof = prover.prove_core(&pk, &stdin).unwrap();

    tracing::info!("compress");
    let compressed_proof = prover.compress(&vk, core_proof, vec![]).unwrap();

    tracing::info!("shrink");
    let shrink_proof = prover.shrink(compressed_proof).unwrap();

    tracing::info!("wrap");
    let wrapped_proof = prover.wrap_bn254(shrink_proof).unwrap();

    (prover.wrap_vk, wrapped_proof.proof)
}
