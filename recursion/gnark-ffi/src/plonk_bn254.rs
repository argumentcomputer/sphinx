use std::{fs::File, io::Write, path::Path};

use crate::{
    ffi::{build_plonk_bn254, prove_plonk_bn254, test_plonk_bn254, verify_plonk_bn254},
    witness::GnarkWitness,
};

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sphinx_recursion_compiler::{
    constraints::Constraint,
    ir::{Config, Witness},
};

/// A prover that can generate proofs with the PLONK protocol using bindings to Gnark.
#[derive(Debug, Clone)]
pub struct PlonkBn254Prover;

/// A zero-knowledge proof generated by the PLONK protocol with a Base64 encoded gnark PLONK proof.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlonkBn254Proof {
    pub public_inputs: [String; 2],
    pub encoded_proof: String,
    pub raw_proof: String,
}

impl PlonkBn254Prover {
    /// Creates a new [PlonkBn254Prover].
    pub fn new() -> Self {
        Self
    }

    /// Executes the prover in testing mode with a circuit definition and witness.
    pub fn test<C: Config>(constraints: &[Constraint], witness: Witness<C>) {
        let serialized = serde_json::to_string(&constraints).unwrap();

        // Write constraints.
        let mut constraints_file = tempfile::NamedTempFile::new().unwrap();
        constraints_file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let mut witness_file = tempfile::NamedTempFile::new().unwrap();
        let gnark_witness = GnarkWitness::new(witness);
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        witness_file.write_all(serialized.as_bytes()).unwrap();

        test_plonk_bn254(
            witness_file.path().to_str().unwrap(),
            constraints_file.path().to_str().unwrap(),
        );
    }

    /// Builds the PLONK circuit locally.
    pub fn build<C: Config>(constraints: &[Constraint], witness: Witness<C>, build_dir: &Path) {
        let serialized = serde_json::to_string(&constraints).unwrap();

        // Write constraints.
        let constraints_path = build_dir.join("constraints.json");
        let mut file = File::create(constraints_path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let witness_path = build_dir.join("witness.json");
        let gnark_witness = GnarkWitness::new(witness);
        let mut file = File::create(witness_path).unwrap();
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        build_plonk_bn254(build_dir.to_str().unwrap());

        // Write the corresponding asset files to the build dir.
        let sphinx_mock_verifier_path = build_dir.join("SP1MockVerifier.sol");
        let sphinx_mock_verifier_str = include_str!("../assets/SP1MockVerifier.txt");
        let mut mock_verifier_file = File::create(sphinx_mock_verifier_path).unwrap();
        mock_verifier_file
            .write_all(sphinx_mock_verifier_str.as_bytes())
            .unwrap();

        let sphinx_verifier_path = build_dir.join("SP1Verifier.sol");
        let sphinx_verifier_str = include_str!("../assets/SP1Verifier.txt");
        let mut sphinx_verifier_file = File::create(sphinx_verifier_path).unwrap();
        sphinx_verifier_file
            .write_all(sphinx_verifier_str.as_bytes())
            .unwrap();

        let interface_sphinx_verifier_path = build_dir.join("ISP1Verifier.sol");
        let interface_sphinx_verifier_str = include_str!("../assets/ISP1Verifier.txt");
        let mut interface_sphinx_verifier_file =
            File::create(interface_sphinx_verifier_path).unwrap();
        interface_sphinx_verifier_file
            .write_all(interface_sphinx_verifier_str.as_bytes())
            .unwrap();
    }

    /// Generates a PLONK proof by sending a request to the Gnark server.
    pub fn prove<C: Config>(&self, witness: Witness<C>, build_dir: &Path) -> PlonkBn254Proof {
        // Write witness.
        let mut witness_file = tempfile::NamedTempFile::new().unwrap();
        let gnark_witness = GnarkWitness::new(witness);
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        witness_file.write_all(serialized.as_bytes()).unwrap();

        prove_plonk_bn254(
            build_dir.to_str().unwrap(),
            witness_file.path().to_str().unwrap(),
        )
    }

    /// Verify a PLONK proof and verify that the supplied vkey_hash and committed_values_digest match.
    pub fn verify(
        &self,
        proof: &PlonkBn254Proof,
        vkey_hash: &BigUint,
        committed_values_digest: &BigUint,
        build_dir: &Path,
    ) {
        verify_plonk_bn254(
            build_dir.to_str().unwrap(),
            &proof.raw_proof,
            &vkey_hash.to_string(),
            &committed_values_digest.to_string(),
        )
        .expect("failed to verify proof")
    }
}

impl Default for PlonkBn254Prover {
    fn default() -> Self {
        Self::new()
    }
}
