#![allow(unused)]
pub mod tests {
    /// Demos.

    pub const CHESS_ELF: &[u8] =
        include_bytes!("../../../examples/chess/program/elf/riscv32im-succinct-zkvm-elf");

    pub const FIBONACCI_IO_ELF: &[u8] =
        include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

    pub const IO_ELF: &[u8] =
        include_bytes!("../../../examples/io/program/elf/riscv32im-succinct-zkvm-elf");

    pub const JSON_ELF: &[u8] =
        include_bytes!("../../../examples/json/program/elf/riscv32im-succinct-zkvm-elf");

    pub const REGEX_ELF: &[u8] =
        include_bytes!("../../../examples/regex/program/elf/riscv32im-succinct-zkvm-elf");

    pub const RSA_ELF: &[u8] =
        include_bytes!("../../../examples/rsa/program/elf/riscv32im-succinct-zkvm-elf");

    pub const SSZ_WITHDRAWALS_ELF: &[u8] =
        include_bytes!("../../../examples/ssz-withdrawals/program/elf/riscv32im-succinct-zkvm-elf");

    pub const TENDERMINT_ELF: &[u8] =
        include_bytes!("../../../examples/tendermint/program/elf/riscv32im-succinct-zkvm-elf");

    /// Tests.

    pub const FIBONACCI_ELF: &[u8] =
        include_bytes!("../../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");

    pub const ED25519_ELF: &[u8] =
        include_bytes!("../../../tests/ed25519/elf/riscv32im-succinct-zkvm-elf");

    pub const CYCLE_TRACKER_ELF: &[u8] =
        include_bytes!("../../../tests/cycle-tracker/elf/riscv32im-succinct-zkvm-elf");

    pub const ECRECOVER_ELF: &[u8] =
        include_bytes!("../../../tests/ecrecover/elf/riscv32im-succinct-zkvm-elf");

    pub const ED_ADD_ELF: &[u8] =
        include_bytes!("../../../tests/ed-add/elf/riscv32im-succinct-zkvm-elf");

    pub const ED_DECOMPRESS_ELF: &[u8] =
        include_bytes!("../../../tests/ed-decompress/elf/riscv32im-succinct-zkvm-elf");

    pub const KECCAK_PERMUTE_ELF: &[u8] =
        include_bytes!("../../../tests/keccak-permute/elf/riscv32im-succinct-zkvm-elf");

    pub const KECCAK256_ELF: &[u8] =
        include_bytes!("../../../tests/keccak256/elf/riscv32im-succinct-zkvm-elf");

    pub const SECP256K1_ADD_ELF: &[u8] =
        include_bytes!("../../../tests/secp256k1-add/elf/riscv32im-succinct-zkvm-elf");

    pub const SECP256K1_DECOMPRESS_ELF: &[u8] =
        include_bytes!("../../../tests/secp256k1-decompress/elf/riscv32im-succinct-zkvm-elf");

    pub const SECP256K1_DOUBLE_ELF: &[u8] =
        include_bytes!("../../../tests/secp256k1-double/elf/riscv32im-succinct-zkvm-elf");

    pub const SHA_COMPRESS_ELF: &[u8] =
        include_bytes!("../../../tests/sha-compress/elf/riscv32im-succinct-zkvm-elf");

    pub const SHA_EXTEND_ELF: &[u8] =
        include_bytes!("../../../tests/sha-extend/elf/riscv32im-succinct-zkvm-elf");

    pub const SHA2_ELF: &[u8] =
        include_bytes!("../../../tests/sha2/elf/riscv32im-succinct-zkvm-elf");

    pub const BN254_ADD_ELF: &[u8] =
        include_bytes!("../../../tests/bn254-add/elf/riscv32im-succinct-zkvm-elf");

    pub const BN254_DOUBLE_ELF: &[u8] =
        include_bytes!("../../../tests/bn254-double/elf/riscv32im-succinct-zkvm-elf");

    pub const BN254_MUL_ELF: &[u8] =
        include_bytes!("../../../tests/bn254-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_G1_ADD_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-g1-add/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_G1_DOUBLE_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-g1-double/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_G1_SCALARMUL_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-g1-scalarmul/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_FP_ADD_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-fp-add/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_FP_SUB_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-fp-sub/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_FP_MUL_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-fp-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_FP2_ADD_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-fp2-add/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_FP2_SUB_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-fp2-sub/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_FP2_MUL_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-fp2-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_G1_DECOMPRESS_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-g1-decompress/elf/riscv32im-succinct-zkvm-elf");

    pub const SECP256K1_MUL_ELF: &[u8] =
        include_bytes!("../../../tests/secp256k1-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const VERIFY_PROOF_ELF: &[u8] =
        include_bytes!("../../../tests/verify-proof/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_G2_ADD_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-g2-add/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_G2_DOUBLE_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-g2-double/elf/riscv32im-succinct-zkvm-elf");

    pub const BLAKE2S_XOR_RIGHT_ROTATE_ELF: &[u8] =
        include_bytes!("../../../tests/blake2s-xor-rotate-right/elf/riscv32im-succinct-zkvm-elf");

    pub const BLAKE2S_XOR_RIGHT_16_ELF: &[u8] =
        include_bytes!("../../../tests/blake2s-xor-rotate-16/elf/riscv32im-succinct-zkvm-elf");

    pub const PANIC_ELF: &[u8] =
        include_bytes!("../../../tests/panic/elf/riscv32im-succinct-zkvm-elf");
}
