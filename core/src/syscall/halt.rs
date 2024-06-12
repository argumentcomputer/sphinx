use crate::runtime::{Syscall, SyscallContext};

pub struct SyscallHalt;

impl SyscallHalt {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for SyscallHalt {
    fn default() -> Self {
        Self::new()
    }
}

impl Syscall for SyscallHalt {
    fn execute(&self, ctx: &mut SyscallContext<'_>, exit_code: u32, _: u32) -> Option<u32> {
        ctx.set_next_pc(0);
        ctx.set_exit_code(exit_code);
        None
    }
}
