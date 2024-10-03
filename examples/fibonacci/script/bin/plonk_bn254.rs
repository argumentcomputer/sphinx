use sphinx_sdk::{utils, ProverClient, SphinxStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write '500' to it.
    let n = 500u32;

    let mut stdin = SphinxStdin::new();
    stdin.write(&n);

    // Generate the proof for the given program and input.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, stdin).plonk().run().unwrap();

    println!("generated proof");

    // Get the public values as bytes.
    let public_values = proof.public_values.raw();
    println!("public values: {:?}", public_values);

    // Get the proof as bytes.
    let solidity_proof = proof.raw();
    println!("proof: {:?}", solidity_proof);

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Save the proof.
    proof
        .save("proof-with-pis.bin")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
