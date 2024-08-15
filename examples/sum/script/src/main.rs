use sphinx_sdk::{utils, ProverClient, SphinxProof, SphinxStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write input to it.
    let nums: Vec<u64> = (0..1000).collect::<Vec<_>>();

    let mut stdin = SphinxStdin::new();
    stdin.write(&nums);

    // Generate the proof for the given program and input.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).unwrap();

    println!("generated proof");

    // Read and verify the output.
    let input = proof.public_values.read::<Vec<u64>>();
    let output = proof.public_values.read::<u64>();

    println!("input: 0..{}", input.len());
    println!("output: {}", output);

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof
        .save("proof-with-pis.bin")
        .expect("saving proof failed");
    let deserialized_proof = SphinxProof::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client
        .verify(&deserialized_proof, &vk)
        .expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
