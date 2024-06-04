#![allow(clippy::needless_range_loop)]

extern crate alloc;

pub mod asm;
pub mod config;
pub mod constraints;
pub mod ir;
pub mod util;

pub mod prelude {
    pub use sphinx_recursion_derive::DslVariable;

    pub use crate::{asm::AsmCompiler, ir::*};
}
