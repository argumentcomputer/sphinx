use crate::runtime::{Register, Syscall, SyscallContext};

pub struct SyscallHalt;

impl SyscallHalt {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SyscallHalt {
    fn default() -> Self {
        Self::new()
    }
}

impl Syscall for SyscallHalt {
    fn execute(&self, ctx: &mut SyscallContext<'_>, _: u32, _: u32) -> Option<u32> {
        let exit_code = ctx.register_unsafe(Register::X10);
        assert!(!(ctx.rt.fail_on_panic && exit_code != 0),
            "RISC-V runtime halted during program execution with non-zero exit code {exit_code}. This likely means your program panicked during execution."
        );
        ctx.set_next_pc(0);
        None
    }
}
