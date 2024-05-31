pub mod config;
pub mod poseidon2;
pub mod utils;

use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use sphinx_core::stark::{Chip, StarkGenericConfig, StarkMachine, PROOF_MAX_NUM_PVS};
use sphinx_derive::{EventLens, MachineAir, WithEvents};

use crate::runtime::D;
use crate::{
    cpu::CpuChip, fri_fold::FriFoldChip, memory::MemoryGlobalChip, multi::MultiChip,
    poseidon2::Poseidon2Chip, poseidon2_wide::Poseidon2WideChip, program::ProgramChip,
    range_check::RangeCheckChip,
};
use core::iter::once;
use std::marker::PhantomData;

pub type RecursionAirWideDeg3<F> = RecursionAir<F, 3>;
pub type RecursionAirSkinnyDeg7<F> = RecursionAir<F, 7>;

#[derive(WithEvents, EventLens, MachineAir)]
#[sphinx_core_path = "sphinx_core"]
#[execution_record_path = "crate::runtime::ExecutionRecord<F>"]
#[program_path = "crate::runtime::RecursionProgram<F>"]
#[builder_path = "crate::air::SphinxRecursionAirBuilder<F = F>"]
#[record_type = "crate::runtime::ExecutionRecord<F>"]
pub enum RecursionAir<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize> {
    Program(ProgramChip<F>),
    Cpu(CpuChip<F>),
    MemoryGlobal(MemoryGlobalChip<F>),
    Poseidon2Wide(Poseidon2WideChip<F, DEGREE>),
    Poseidon2Skinny(Poseidon2Chip<F>),
    FriFold(FriFoldChip<F, DEGREE>),
    RangeCheck(RangeCheckChip<F>),
    Multi(MultiChip<F, DEGREE>),
}

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize> RecursionAir<F, DEGREE> {
    /// A recursion machine that can have dynamic trace sizes.
    pub fn machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::get_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    /// A recursion machine with fixed trace sizes tuned to work specifically for the wrap layer.
    pub fn wrap_machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::get_wrap_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    pub fn get_all() -> Vec<Self> {
        once(RecursionAir::Program(ProgramChip(PhantomData)))
            .chain(once(RecursionAir::Cpu(CpuChip {
                fixed_log2_rows: None,
                _phantom: PhantomData,
            })))
            .chain(once(RecursionAir::MemoryGlobal(MemoryGlobalChip {
                fixed_log2_rows: None,
                _phantom: PhantomData,
            })))
            .chain(once(RecursionAir::Poseidon2Wide(Poseidon2WideChip::<
                F,
                DEGREE,
            > {
                fixed_log2_rows: None,
                _phantom: PhantomData,
            })))
            .chain(once(RecursionAir::FriFold(FriFoldChip::<F, DEGREE> {
                fixed_log2_rows: None,
                _phantom: PhantomData,
            })))
            .chain(once(RecursionAir::RangeCheck(RangeCheckChip::default())))
            .collect()
    }

    pub fn get_wrap_all() -> Vec<Self> {
        once(RecursionAir::Program(ProgramChip(PhantomData)))
            .chain(once(RecursionAir::Cpu(CpuChip {
                fixed_log2_rows: Some(20),
                _phantom: PhantomData,
            })))
            .chain(once(RecursionAir::MemoryGlobal(MemoryGlobalChip {
                fixed_log2_rows: Some(20),
                _phantom: PhantomData,
            })))
            .chain(once(RecursionAir::Multi(MultiChip {
                fixed_log2_rows: Some(20),
                _phantom: PhantomData,
            })))
            .chain(once(RecursionAir::RangeCheck(RangeCheckChip::default())))
            .collect()
    }
}
