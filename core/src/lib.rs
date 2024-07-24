#![allow(
    clippy::new_without_default,
    clippy::field_reassign_with_default,
    clippy::needless_range_loop,
    deprecated
)]
#![warn(unused_extern_crates)]

pub mod air;
pub mod alu;
pub mod bytes;
pub mod cpu;
pub mod disassembler;
pub mod io;
pub mod lookup;
pub mod memory;
pub mod operations;
pub mod program;
pub mod runtime;
pub mod stark;
pub mod syscall;
pub mod utils;

#[allow(unused_imports)]
use runtime::{Program, Runtime};
use stark::StarkGenericConfig;

/// The global version for all components of SP1.
///
/// This string should be updated whenever any step in verifying an SP1 proof changes, including
/// core, recursion, and plonk-bn254. This string is used to download SP1 artifacts and the gnark
/// docker image.
pub const SPHINX_CIRCUIT_VERSION: &str = "v1.0.7-testnet";
