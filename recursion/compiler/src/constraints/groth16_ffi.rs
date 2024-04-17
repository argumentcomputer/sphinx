use std::{
    fs::File,
    io::Write,
    process::{Command, Stdio},
};

use p3_field::{AbstractExtensionField, AbstractField, PrimeField};
use serde::{Deserialize, Serialize};

use super::Constraint;
use crate::prelude::{Config, Witness};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Groth16Witness {
    pub vars: Vec<String>,
    pub felts: Vec<String>,
    pub exts: Vec<Vec<String>>,
}

pub fn prove<C: Config>(constraints: &[Constraint], mut witness: Witness<C>) {
    let serialized = serde_json::to_string(&constraints).unwrap();
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dir = format!("{}/../groth16", manifest_dir);

    // Append some dummy elements to the witness to avoid compilation errors.
    witness.vars.push(C::N::from_canonical_usize(999));
    witness.felts.push(C::F::from_canonical_usize(999));
    witness.exts.push(C::EF::from_canonical_usize(999));

    // Write constraints.
    let constraints_path = format!("{}/constraints.json", dir);
    let mut file = File::create(constraints_path).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();

    // Write witness.
    let witness_path = format!("{}/witness.json", dir);
    let gnark_witness = Groth16Witness {
        vars: witness
            .vars
            .into_iter()
            .map(|w| w.as_canonical_biguint().to_string())
            .collect(),
        felts: witness
            .felts
            .into_iter()
            .map(|w| w.as_canonical_biguint().to_string())
            .collect(),
        exts: witness
            .exts
            .into_iter()
            .map(|w| {
                w.as_base_slice()
                    .iter()
                    .map(|x| x.as_canonical_biguint().to_string())
                    .collect()
            })
            .collect(),
    };
    let mut file = File::create(witness_path).unwrap();
    let serialized = serde_json::to_string(&gnark_witness).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();

    let result = Command::new("go")
        .args([
            "test",
            "-v",
            "-timeout",
            "100000s",
            "-run",
            "^TestMain$",
            "github.com/succinctlabs/sp1-recursion-groth16",
        ])
        .current_dir(dir)
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stdin(Stdio::inherit())
        .output()
        .unwrap();

    assert!(result.status.success(), "failed to run test circuit");
}
