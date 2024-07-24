<<<<<<< HEAD
use sphinx_sdk::{utils, ProverClient, SphinxStdin};
||||||| parent of 642efdd62 (feat: catch-up to testnet v1.0.7)
use sphinx_sdk::{utils, ProverClient, SphinxStdin};
=======
use sphinx_sdk::{utils, ProverClient, SphinxProof, SphinxStdin};
>>>>>>> 642efdd62 (feat: catch-up to testnet v1.0.7)

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    // utils::setup_tracer();
    utils::setup_logger();

    let stdin = SphinxStdin::new();
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, stdin).expect("proving failed");

    // Verify proof.
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
