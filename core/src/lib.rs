#![allow(
    clippy::new_without_default,
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
