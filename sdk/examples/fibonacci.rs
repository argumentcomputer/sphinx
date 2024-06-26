use sphinx_sdk::{utils, ProverClient, SphinxStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] =
    include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

/// RUST_LOG=debug RUST_LOGGER=texray cargo run --release --example fibonacci --package sphinx-sdk
fn main() {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write '500' to it.
    let n = 1000u32;

    let mut stdin = SphinxStdin::new();
    stdin.write(&n);

    // Generate the proof for the given program and input.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = tracing_texray::examine(tracing::info_span!("bang!"))
        .in_scope(|| client.prove_plonk(&pk, stdin).unwrap());

    println!("generated proof");

    // Read and verify the output.
    let _ = proof.public_values.read::<u32>();
    let a = proof.public_values.read::<u32>();
    let b = proof.public_values.read::<u32>();

    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof and public values
    client
        .verify_plonk(&proof, &vk)
        .expect("verification failed");

    // Save the proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified plonk proof for the program!")
}
