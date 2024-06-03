use serde::{Deserialize, Serialize};
use sphinx_sdk::{utils, ProverClient, SphinxStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct MyPointUnaligned {
    pub x: usize,
    pub y: usize,
    pub b: bool,
}

fn main() {
    // Setup a tracer for logging.
    utils::setup_logger();

    // Create an input stream.
    let mut stdin = SphinxStdin::new();
    let p = MyPointUnaligned {
        x: 1,
        y: 2,
        b: true,
    };
    let q = MyPointUnaligned {
        x: 3,
        y: 4,
        b: false,
    };
    stdin.write(&p);
    stdin.write(&q);

    // Generate the proof for the given program.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).unwrap();

    // Read the output.
    let r = proof.public_values.read::<MyPointUnaligned>();
    println!("r: {:?}", r);

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Save the proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
