//! A simple example showing how to aggregate proofs of multiple programs with SP1.

use sphinx_sdk::{
    HashableKey, ProverClient, SphinxProof, SphinxProofWithPublicValues, SphinxStdin, SphinxVerifyingKey,
};

/// A program that aggregates the proofs of the simple program.
const AGGREGATION_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

/// A program that just runs a simple computation.
const FIBONACCI_ELF: &[u8] =
    include_bytes!("../../../fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

/// An input to the aggregation program.
///
/// Consists of a proof and a verification key.
struct AggregationInput {
    pub proof: SphinxProofWithPublicValues,
    pub vk: SphinxVerifyingKey,
}

fn main() {
    // Setup the logger.
    sphinx_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (aggregation_pk, _) = client.setup(AGGREGATION_ELF);
    let (fibonacci_pk, fibonacci_vk) = client.setup(FIBONACCI_ELF);

    // Generate the fibonacci proofs.
    let proof_1 = tracing::info_span!("generate fibonacci proof n=10").in_scope(|| {
        let mut stdin = SphinxStdin::new();
        stdin.write(&10);
        client
            .prove(&fibonacci_pk, stdin)
            .compressed()
            .run()
            .expect("proving failed")
    });
    let proof_2 = tracing::info_span!("generate fibonacci proof n=20").in_scope(|| {
        let mut stdin = SphinxStdin::new();
        stdin.write(&20);
        client
            .prove(&fibonacci_pk, stdin)
            .compressed()
            .run()
            .expect("proving failed")
    });
    let proof_3 = tracing::info_span!("generate fibonacci proof n=30").in_scope(|| {
        let mut stdin = SphinxStdin::new();
        stdin.write(&30);
        client
            .prove(&fibonacci_pk, stdin)
            .compressed()
            .run()
            .expect("proving failed")
    });

    // Setup the inputs to the aggregation program.
    let input_1 = AggregationInput {
        proof: proof_1,
        vk: fibonacci_vk.clone(),
    };
    let input_2 = AggregationInput {
        proof: proof_2,
        vk: fibonacci_vk.clone(),
    };
    let input_3 = AggregationInput {
        proof: proof_3,
        vk: fibonacci_vk.clone(),
    };
    let inputs = vec![input_1, input_2, input_3];

    // Aggregate the proofs.
    tracing::info_span!("aggregate the proofs").in_scope(|| {
        let mut stdin = SphinxStdin::new();

        // Write the verification keys.
        let vkeys = inputs
            .iter()
            .map(|input| input.vk.hash_u32())
            .collect::<Vec<_>>();
        stdin.write::<Vec<[u32; 8]>>(&vkeys);

        // Write the public values.
        let public_values = inputs
            .iter()
            .map(|input| input.proof.public_values.to_vec())
            .collect::<Vec<_>>();
        stdin.write::<Vec<Vec<u8>>>(&public_values);

        // Write the proofs.
        //
        // Note: this data will not actually be read by the aggregation program, instead it will be
        // witnessed by the prover during the recursive aggregation process inside SP1 itself.
        for input in inputs {
            let SphinxProof::Compressed(proof) = input.proof.proof else {
                panic!()
            };
            stdin.write_proof(proof, input.vk.vk);
        }

        // Generate the plonk bn254 proof.
        client
            .prove(&aggregation_pk, stdin)
            .plonk()
            .run()
            .expect("proving failed");
    });
}
