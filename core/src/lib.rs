#![allow(
    clippy::field_reassign_with_default,
    clippy::needless_range_loop,
    deprecated
)]

extern crate alloc;

pub mod air;
pub mod alu;
pub mod bytes;
pub mod cpu;
pub mod disassembler;
#[deprecated(note = "Import from wp1_sdk instead of wp1_core")]
pub mod io;
pub mod lookup;
pub mod memory;
pub mod operations;
pub mod program;
pub mod runtime;
pub mod stark;
pub mod syscall;
pub mod utils;

pub use io::*;
#[allow(unused_imports)]
use runtime::{Program, Runtime};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use stark::{Proof, StarkGenericConfig};

/// A proof of a RISCV ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize)]
#[deprecated(note = "Import from wp1_sdk instead of wp1_core")]
pub struct SP1ProofWithIO<SC: StarkGenericConfig + Serialize + DeserializeOwned> {
    #[serde(with = "proof_serde")]
    pub proof: Proof<SC>,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
}
