use super::StarkMachine;
pub use crate::air::SphinxAirBuilder;
use crate::air::{MachineAir, SPHINX_PROOF_NUM_PV_ELTS};
use crate::memory::{MemoryChipType, MemoryProgramChip};
use crate::stark::Chip;
use crate::syscall::precompiles::bls12_381::g1_decompress::Bls12381G1DecompressChip;
use crate::syscall::precompiles::bls12_381::g2_add::Bls12381G2AffineAddChip;
use crate::syscall::precompiles::bls12_381::g2_double::Bls12381G2AffineDoubleChip;
use crate::syscall::precompiles::field::add::FieldAddChip;
use crate::syscall::precompiles::field::mul::FieldMulChip;
use crate::syscall::precompiles::field::sub::FieldSubChip;
use crate::syscall::precompiles::quad_field::add::QuadFieldAddChip;
use crate::syscall::precompiles::quad_field::mul::QuadFieldMulChip;
use crate::syscall::precompiles::quad_field::sub::QuadFieldSubChip;
use crate::syscall::precompiles::secp256k1::decompress::Secp256k1DecompressChip;
use crate::utils::ec::weierstrass::bls12_381::Bls12381BaseField;
use crate::StarkGenericConfig;
use p3_field::PrimeField32;
pub use riscv_chips::*;
use sphinx_derive::{EventLens, WithEvents};
use tracing::instrument;

/// A module for importing all the different RISC-V chips.
pub(crate) mod riscv_chips {
    pub use crate::alu::AddSubChip;
    pub use crate::alu::BitwiseChip;
    pub use crate::alu::DivRemChip;
    pub use crate::alu::LtChip;
    pub use crate::alu::MulChip;
    pub use crate::alu::ShiftLeft;
    pub use crate::alu::ShiftRightChip;
    pub use crate::bytes::ByteChip;
    pub use crate::cpu::CpuChip;
    pub use crate::memory::MemoryChip;
    pub use crate::program::ProgramChip;
    pub use crate::syscall::precompiles::edwards::EdAddAssignChip;
    pub use crate::syscall::precompiles::edwards::EdDecompressChip;
    pub use crate::syscall::precompiles::keccak256::KeccakPermuteChip;
    pub use crate::syscall::precompiles::sha256::ShaCompressChip;
    pub use crate::syscall::precompiles::sha256::ShaExtendChip;
    pub use crate::syscall::precompiles::weierstrass::WeierstrassAddAssignChip;
    pub use crate::syscall::precompiles::weierstrass::WeierstrassDoubleAssignChip;
    pub use crate::utils::ec::edwards::ed25519::Ed25519Parameters;
    pub use crate::utils::ec::edwards::EdwardsCurve;
    pub use crate::utils::ec::weierstrass::bls12_381::Bls12381Parameters;
    pub use crate::utils::ec::weierstrass::bn254::Bn254Parameters;
    pub use crate::utils::ec::weierstrass::secp256k1::Secp256k1Parameters;
    pub use crate::utils::ec::weierstrass::SwCurve;
}

/// An AIR for encoding RISC-V execution.
///
/// This enum contains all the different AIRs that are used in the Sp1 RISC-V IOP. Each variant is
/// a different AIR that is used to encode a different part of the RISC-V execution, and the
/// different AIR variants have a joint lookup argument.
#[derive(WithEvents, EventLens, MachineAir)]
#[record_type = "crate::runtime::ExecutionRecord"]
pub enum RiscvAir<F: PrimeField32> {
    /// An AIR that contains a preprocessed program table and a lookup for the instructions.
    Program(ProgramChip),
    /// An AIR for the RISC-V CPU. Each row represents a cpu cycle.
    Cpu(CpuChip),
    /// An AIR for the RISC-V Add and SUB instruction.
    Add(AddSubChip),
    /// An AIR for RISC-V Bitwise instructions.
    Bitwise(BitwiseChip),
    /// An AIR for RISC-V Mul instruction.
    Mul(MulChip),
    /// An AIR for RISC-V Div and Rem instructions.
    DivRem(DivRemChip),
    /// An AIR for RISC-V Lt instruction.
    Lt(LtChip),
    /// An AIR for RISC-V SLL instruction.
    ShiftLeft(ShiftLeft),
    /// An AIR for RISC-V SRL and SRA instruction.
    ShiftRight(ShiftRightChip),
    /// A lookup table for byte operations.
    ByteLookup(ByteChip<F>),
    /// A table for initializing the memory state.
    MemoryInit(MemoryChip),
    /// A table for finalizing the memory state.
    MemoryFinal(MemoryChip),
    /// A table for initializing the program memory.
    ProgramMemory(MemoryProgramChip),
    /// A precompile for sha256 extend.
    Sha256Extend(ShaExtendChip),
    /// A precompile for sha256 compress.
    Sha256Compress(ShaCompressChip),
    /// A precompile for addition on the Elliptic curve ed25519.
    Ed25519Add(EdAddAssignChip<EdwardsCurve<Ed25519Parameters>>),
    /// A precompile for decompressing a point on the Edwards curve ed25519.
    Ed25519Decompress(EdDecompressChip<Ed25519Parameters>),
    /// A precompile for decompressing a point on the K256 curve.
    Secp256k1Decompress(Secp256k1DecompressChip),
    /// A precompile for addition on the Elliptic curve secp256k1.
    Secp256k1Add(WeierstrassAddAssignChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve secp256k1.
    Secp256k1Double(WeierstrassDoubleAssignChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for the Keccak permutation.
    KeccakP(KeccakPermuteChip),
    /// A precompile for addition on the Elliptic curve bn254.
    Bn254Add(WeierstrassAddAssignChip<SwCurve<Bn254Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve bn254.
    Bn254Double(WeierstrassDoubleAssignChip<SwCurve<Bn254Parameters>>),
    /// A precompile for G1 point addition on the Elliptic curve bls12_381.
    Bls12381Add(WeierstrassAddAssignChip<SwCurve<Bls12381Parameters>>),
    /// A precompile for doubling a G1 point on the Elliptic curve bls12_381.
    Bls12381Double(WeierstrassDoubleAssignChip<SwCurve<Bls12381Parameters>>),
    /// A precompile for addition of BLS12-381 field elements.
    Bls12381FpAdd(FieldAddChip<Bls12381BaseField>),
    /// A precompile for subtraction of BLS12-381 field elements.
    Bls12381FpSub(FieldSubChip<Bls12381BaseField>),
    /// A precompile for multiplication of BLS12-381 field elements.
    Bls12381FpMul(FieldMulChip<Bls12381BaseField>),
    /// A precompile for addition of BLS12-381 quadratic extension field elements.
    Bls12381Fp2Add(QuadFieldAddChip<Bls12381BaseField>),
    /// A precompile for subtraction of BLS12-381 quadratic field elements.
    Bls12381Fp2Sub(QuadFieldSubChip<Bls12381BaseField>),
    /// A precompile for multiplication of BLS12-381 quadratic field elements.
    Bls12381Fp2Mul(QuadFieldMulChip<Bls12381BaseField>),
    /// A precompile for decompressing a point on the BLS12-381 curve.
    Bls12381G1Decompress(Bls12381G1DecompressChip),
    /// A precompile for adding two G2Affine points on the BLS12-381 curve.
    Bls12381G2Add(Bls12381G2AffineAddChip),
    /// A precompile for doubling a G2Affine point on the BLS12-381 curve.
    Bls12381G2AffineDouble(Bls12381G2AffineDoubleChip),
}

impl<F: PrimeField32> RiscvAir<F> {
    #[instrument("construct RiscvAir machine", level = "debug", skip_all)]
    pub fn machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::get_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        StarkMachine::new(config, chips, SPHINX_PROOF_NUM_PV_ELTS)
    }

    /// Get all the different RISC-V AIRs.
    pub fn get_all() -> Vec<Self> {
        // The order of the chips is important, as it is used to determine the order of trace
        // generation. In the future, we will detect that order automatically.
        let mut chips = vec![];
        let cpu = CpuChip;
        chips.push(RiscvAir::Cpu(cpu));
        let program = ProgramChip;
        chips.push(RiscvAir::Program(program));
        let sha_extend = ShaExtendChip;
        chips.push(RiscvAir::Sha256Extend(sha_extend));
        let sha_compress = ShaCompressChip;
        chips.push(RiscvAir::Sha256Compress(sha_compress));
        let ed_add_assign = EdAddAssignChip::<EdwardsCurve<Ed25519Parameters>>::new();
        chips.push(RiscvAir::Ed25519Add(ed_add_assign));
        let ed_decompress = EdDecompressChip::<Ed25519Parameters>::default();
        chips.push(RiscvAir::Ed25519Decompress(ed_decompress));
        let k256_decompress = Secp256k1DecompressChip::new();
        chips.push(RiscvAir::Secp256k1Decompress(k256_decompress));
        let secp256k1_add_assign = WeierstrassAddAssignChip::<SwCurve<Secp256k1Parameters>>::new();
        chips.push(RiscvAir::Secp256k1Add(secp256k1_add_assign));
        let secp256k1_double_assign =
            WeierstrassDoubleAssignChip::<SwCurve<Secp256k1Parameters>>::new();
        chips.push(RiscvAir::Secp256k1Double(secp256k1_double_assign));
        let keccak_permute = KeccakPermuteChip::new();
        chips.push(RiscvAir::KeccakP(keccak_permute));
        let bn254_add_assign = WeierstrassAddAssignChip::<SwCurve<Bn254Parameters>>::new();
        chips.push(RiscvAir::Bn254Add(bn254_add_assign));
        let bn254_double_assign = WeierstrassDoubleAssignChip::<SwCurve<Bn254Parameters>>::new();
        chips.push(RiscvAir::Bn254Double(bn254_double_assign));
        let bls12381_g1_add = WeierstrassAddAssignChip::<SwCurve<Bls12381Parameters>>::new();
        chips.push(RiscvAir::Bls12381Add(bls12381_g1_add));
        let bls12381_g1_double = WeierstrassDoubleAssignChip::<SwCurve<Bls12381Parameters>>::new();
        chips.push(RiscvAir::Bls12381Double(bls12381_g1_double));
        let bls12381_fp_add = FieldAddChip::<Bls12381BaseField>::new();
        chips.push(RiscvAir::Bls12381FpAdd(bls12381_fp_add));
        let bls12381_fp_sub = FieldSubChip::<Bls12381BaseField>::new();
        chips.push(RiscvAir::Bls12381FpSub(bls12381_fp_sub));
        let bls12381_fp_mul = FieldMulChip::<Bls12381BaseField>::new();
        chips.push(RiscvAir::Bls12381FpMul(bls12381_fp_mul));
        let bls12381_fp2_add = QuadFieldAddChip::<Bls12381BaseField>::new();
        chips.push(RiscvAir::Bls12381Fp2Add(bls12381_fp2_add));
        let bls12381_fp2_sub = QuadFieldSubChip::<Bls12381BaseField>::new();
        chips.push(RiscvAir::Bls12381Fp2Sub(bls12381_fp2_sub));
        let bls12381_fp2_mul = QuadFieldMulChip::<Bls12381BaseField>::new();
        chips.push(RiscvAir::Bls12381Fp2Mul(bls12381_fp2_mul));
        let bls12381_g1_decompress = Bls12381G1DecompressChip::new();
        chips.push(RiscvAir::Bls12381G1Decompress(bls12381_g1_decompress));
        let bls12381_g2_add = Bls12381G2AffineAddChip::new();
        chips.push(RiscvAir::Bls12381G2Add(bls12381_g2_add));
        let bls12381_g2_double = Bls12381G2AffineDoubleChip::new();
        chips.push(RiscvAir::Bls12381G2AffineDouble(bls12381_g2_double));
        let div_rem = DivRemChip::default();
        chips.push(RiscvAir::DivRem(div_rem));
        let add = AddSubChip::default();
        chips.push(RiscvAir::Add(add));
        let bitwise = BitwiseChip;
        chips.push(RiscvAir::Bitwise(bitwise));
        let mul = MulChip::default();
        chips.push(RiscvAir::Mul(mul));
        let shift_right = ShiftRightChip;
        chips.push(RiscvAir::ShiftRight(shift_right));
        let shift_left = ShiftLeft;
        chips.push(RiscvAir::ShiftLeft(shift_left));
        let lt = LtChip;
        chips.push(RiscvAir::Lt(lt));
        let memory_init = MemoryChip::new(MemoryChipType::Initialize);
        chips.push(RiscvAir::MemoryInit(memory_init));
        let memory_finalize = MemoryChip::new(MemoryChipType::Finalize);
        chips.push(RiscvAir::MemoryFinal(memory_finalize));
        let program_memory_init = MemoryProgramChip::new();
        chips.push(RiscvAir::ProgramMemory(program_memory_init));
        let byte = ByteChip::default();
        chips.push(RiscvAir::ByteLookup(byte));

        chips
    }
}

impl<F: PrimeField32> PartialEq for RiscvAir<F> {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl<F: PrimeField32> Eq for RiscvAir<F> {}

impl<F: PrimeField32> core::hash::Hash for RiscvAir<F> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.name().hash(state);
    }
}
