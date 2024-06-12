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

    let client = ProverClient::new();
    let mut public_values = client.execute(ELF, &stdin).unwrap();

    println!("generated proof");

    // Read and verify the output.
    let _ = public_values.read::<u32>();
    let a = public_values.read::<u32>();
    let b = public_values.read::<u32>();

    println!("a: {}", a);
    println!("b: {}", b);
}
