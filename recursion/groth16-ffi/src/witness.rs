use std::fs::File;
use std::io::Write;

use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::PrimeField;
use serde::Deserialize;
use serde::Serialize;
use wp1_recursion_compiler::ir::Config;
use wp1_recursion_compiler::ir::Witness;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Groth16Witness {
    pub vars: Vec<String>,
    pub felts: Vec<String>,
    pub exts: Vec<Vec<String>>,
}

impl<C: Config> From<Witness<C>> for Groth16Witness {
    fn from(mut witness: Witness<C>) -> Self {
        witness.vars.push(C::N::from_canonical_usize(999));
        witness.felts.push(C::F::from_canonical_usize(999));
        witness.exts.push(C::EF::from_canonical_usize(999));
        Groth16Witness {
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
        }
    }
}

impl Groth16Witness {
    pub fn save(&self, path: &str) {
        let serialized = serde_json::to_string(self).unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();
    }
}
