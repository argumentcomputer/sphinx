use crate::runtime::{Syscall, SyscallContext};

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
    fn execute(&self, ctx: &mut SyscallContext<'_>, exit_code: u32, _: u32) -> Option<u32> {
        let rt = &mut ctx.rt;

        assert!(!rt.fail_on_panic || exit_code == 0,
                "RISC-V runtime halted during program execution with non-zero exit code {}. This likely means your program panicked during execution.",
                exit_code
            );
        ctx.set_next_pc(0);
        ctx.set_exit_code(exit_code);
        None
    }
}
