#[cfg(test)]
mod tests {
    use crate::io::SphinxStdin;
    use crate::Program;
    use crate::utils::{run_test_io, setup_logger};

    #[test]
    fn test_kadena_block_header_hashing() {
        setup_logger();

        let valid_kadena_header = b"AAAAAAAAAADagen7WaIFAASBaVOSlhojqQjImJ0F2PR258lozvJLjkLfXfsEIjPCAwAAAAAAHHEJ8CfvcweMTfvSMBYlXLWv0v25Mt-4bK3RUi_L6lsBAAAAi0pTBul2AUh0jWNPs2LXCdc_sgEyFK01O_bmHgDwkWAIAAAAYzOtui7Ns_-SQp472GrIlRUmIl9UsDagsuZ-Xuzf_L3__________________________________________4dF0GK2zmpsHFv5NYbuvc0pyhXfXwxxJRM0uvq8InFUAwAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAACH1lqeSNBQAAAAAAAAAAAJhcOUndKMtEn5_aPlk_LbLgU-vK_gpvrf14eFWrgEFW".to_vec();
        let mut stdin = SphinxStdin::new();
        stdin.write(&valid_kadena_header);

        let elf = include_bytes!("../../../../../tests/kadena-block-header-hashing/elf/riscv32im-succinct-zkvm-elf");

        let program = Program::from(elf);

        run_test_io(program, &stdin).unwrap();
    }
}