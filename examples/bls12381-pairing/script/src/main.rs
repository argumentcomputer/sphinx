use sphinx_sdk::{utils, ProverClient, SphinxProof, SphinxStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup a tracer for logging.
    utils::setup_logger();

    // Create an input stream.
    let stdin = SphinxStdin::new();

    // Generate the proof for the given program.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, stdin).expect("proving failed");

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof
        .save("proof-with-io.bin")
        .expect("saving proof failed");
    let deserialized_proof = SphinxProof::load("proof-with-io.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client
        .verify(&deserialized_proof, &vk)
        .expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
