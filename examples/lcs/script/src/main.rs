use sphinx_sdk::{utils, ProverClient, SphinxStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write '500' to it.

    let args = ("When in the Course of human events, it becomes necessary for one people to dissolve the political bands which have connected them with another",
       "There must be some kind of way outta here Said the joker to the thief. There's too much confusion. I can't get no relief.");

    let mut stdin = SphinxStdin::new();
    stdin.write(&args);

    // Generate the proof for the given program and input.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove_compressed(&pk, stdin).unwrap();

    println!("generated proof");

    // Why is this not just the single pair of input strings to which the prover committed?
    let _ = proof.public_values.read::<String>();
    let _ = proof.public_values.read::<String>();
    // Read and verify the output.
    let lcs = proof.public_values.read::<String>();

    println!(r#"lcs of "{}" and "{}" is "{lcs}"."#, args.0, args.1);

    // Verify proof and public values
    client
        .verify_compressed(&proof, &vk)
        .expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof
        .save("proof-with-pis.bin")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
