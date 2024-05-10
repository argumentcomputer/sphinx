use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};
use wp1_recursion_compiler::{
    constraints::Constraint,
    ir::{Config, Witness},
};

use crate::witness::GnarkWitness;

/// A prover that can generate proofs with the Groth16 protocol using bindings to Gnark.
pub struct Groth16Prover;

/// A zero-knowledge proof generated by the Groth16 protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Proof {
    pub a: [String; 2],
    pub b: [[String; 2]; 2],
    pub c: [String; 2],
    pub public_inputs: [String; 2],
}

impl Groth16Prover {
    /// Creates a new verifier.
    pub fn new() -> Self {
        Groth16Prover
    }

    /// Executes the prover in testing mode with a circuit definition and witness.
    pub fn test<C: Config>(constraints: &[Constraint], witness: Witness<C>) {
        let serialized = serde_json::to_string(&constraints).unwrap();
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let gnark_dir = format!("{}/../gnark", manifest_dir);

        // Write constraints.
        let mut constraints_file = tempfile::NamedTempFile::new().unwrap();
        constraints_file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let mut witness_file = tempfile::NamedTempFile::new().unwrap();
        let gnark_witness = GnarkWitness::new(witness);
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        witness_file.write_all(serialized.as_bytes()).unwrap();

        // Run `make`.
        let make = Command::new("make")
            .current_dir(&gnark_dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();
        assert!(make.status.success(), "failed to run make");

        let result = Command::new("go")
            .args([
                "test",
                "-tags=prover_checks",
                "-v",
                "-timeout",
                "100000s",
                "-run",
                "^TestMain$",
                "github.com/succinctlabs/sp1-recursion-gnark",
            ])
            .current_dir(gnark_dir)
            .env("WITNESS_JSON", witness_file.path().to_str().unwrap())
            .env(
                "CONSTRAINTS_JSON",
                constraints_file.path().to_str().unwrap(),
            )
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();

        assert!(result.status.success(), "failed to run test circuit");
    }

    pub fn build<C: Config>(constraints: &[Constraint], witness: Witness<C>, build_dir: PathBuf) {
        let serialized = serde_json::to_string(&constraints).unwrap();
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let gnark_dir = manifest_dir.join("../gnark");
        let cwd = std::env::current_dir().unwrap();

        // Write constraints.
        let constraints_path = build_dir.join("constraints_groth16.json");
        let mut file = File::create(constraints_path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let witness_path = build_dir.join("witness_groth16.json");
        let gnark_witness = GnarkWitness::new(witness);
        let mut file = File::create(witness_path).unwrap();
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Run `make`.
        let make = Command::new("make")
            .current_dir(&gnark_dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();
        assert!(make.status.success(), "failed to run make");

        // Run the build script.
        let result = Command::new("go")
            .args([
                "run",
                "main.go",
                "build-groth16",
                "--data",
                cwd.join(build_dir).to_str().unwrap(),
            ])
            .current_dir(gnark_dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();

        assert!(result.status.success(), "failed to run build script");
    }

    pub fn prove<C: Config>(witness: Witness<C>, build_dir: PathBuf) -> Groth16Proof {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let gnark_dir = manifest_dir.join("../gnark");
        let cwd = std::env::current_dir().unwrap();

        // Write witness.
        let mut witness_file = tempfile::NamedTempFile::new().unwrap();
        let gnark_witness = GnarkWitness::new(witness);
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        witness_file.write_all(serialized.as_bytes()).unwrap();

        // Run `make`.
        let make = Command::new("make")
            .current_dir(&gnark_dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();
        assert!(make.status.success(), "failed to run make");

        // Run the prove script.
        let proof_file = tempfile::NamedTempFile::new().unwrap();
        let result = Command::new("go")
            .args([
                "run",
                "main.go",
                "prove-groth16",
                "--data",
                cwd.join(build_dir).to_str().unwrap(),
                "--witness",
                witness_file.path().to_str().unwrap(),
                "--proof",
                proof_file.path().to_str().unwrap(),
            ])
            .current_dir(gnark_dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();

        assert!(result.status.success(), "failed to run build script");

        // Read the contents back from the tempfile.
        let mut buffer = String::new();
        proof_file
            .reopen()
            .unwrap()
            .read_to_string(&mut buffer)
            .unwrap();

        // Deserialize the JSON string back to a Groth16Proof instance
        let deserialized: Groth16Proof =
            serde_json::from_str(&buffer).expect("Error deserializing the proof");

        deserialized
    }
}

impl Default for Groth16Prover {
    fn default() -> Self {
        Self::new()
    }
}
