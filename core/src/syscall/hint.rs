use crate::runtime::{Syscall, SyscallContext};

pub struct SyscallHintLen;

/// SyscallHintLen returns the length of the next slice in the hint input stream.
impl Default for SyscallHintLen {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallHintLen {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallHintLen {
    fn execute(&self, ctx: &mut SyscallContext<'_>, _arg1: u32, _arg2: u32) -> Option<u32> {
        assert!(
            ctx.rt.state.input_stream_ptr < ctx.rt.state.input_stream.len(),
            "not enough vecs in hint input stream"
        );
        Some(ctx.rt.state.input_stream[ctx.rt.state.input_stream_ptr].len() as u32)
    }
}

pub struct SyscallHintRead;

/// SyscallHintRead returns the length of the next slice in the hint input stream.
impl Default for SyscallHintRead {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallHintRead {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallHintRead {
    fn execute(&self, ctx: &mut SyscallContext<'_>, ptr: u32, len: u32) -> Option<u32> {
        assert!(
            ctx.rt.state.input_stream_ptr < ctx.rt.state.input_stream.len(),
            "not enough vecs in hint input stream"
        );
        let vec = &ctx.rt.state.input_stream[ctx.rt.state.input_stream_ptr];
        ctx.rt.state.input_stream_ptr += 1;
        assert!(
            !ctx.rt.unconstrained,
            "hint read should not be used in a unconstrained block"
        );
        assert_eq!(
            vec.len() as u32,
            len,
            "hint input stream read length mismatch"
        );
        assert_eq!(ptr % 4, 0, "hint read address not aligned to 4 bytes");
        // Iterate through the vec in 4-byte chunks
        for i in (0..len).step_by(4) {
            // Get each byte in the chunk
            let b1 = vec[i as usize];
            // In case the vec is not a multiple of 4, right-pad with 0s. This is fine because we
            // are assuming the word is uninitialized, so filling it with 0s makes sense.
            let b2 = vec.get(i as usize + 1).copied().unwrap_or(0);
            let b3 = vec.get(i as usize + 2).copied().unwrap_or(0);
            let b4 = vec.get(i as usize + 3).copied().unwrap_or(0);
            let word = u32::from_le_bytes([b1, b2, b3, b4]);

            // Save the data into runtime state so the runtime will use the desired data instead of
            // 0 when first reading/writing from this address.
            ctx.rt
                .state
                .uninitialized_memory
                .entry(ptr + i)
                .and_modify(|_| panic!("hint read address is initialized already"))
                .or_insert(word);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use crate::{
        io::SP1Stdin,
        runtime::Program,
        utils::{run_and_prove, setup_logger, BabyBearPoseidon2},
    };

    const HINT_IO_ELF: &[u8] =
        include_bytes!("../../../tests/hint-io/elf/riscv32im-succinct-zkvm-elf");

    #[test]
    fn test_hint_io() {
        setup_logger();

        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; 1021];
        rng.fill_bytes(&mut data);

        let mut stdin = SP1Stdin::new();
        stdin.write(&data);
        stdin.write_vec(data);

        let program = Program::from(HINT_IO_ELF);

        let config = BabyBearPoseidon2::new();
        run_and_prove(&program, &stdin, config);
    }
}
