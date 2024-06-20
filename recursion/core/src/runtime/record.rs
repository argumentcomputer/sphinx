use std::array;
use std::sync::Arc;

use hashbrown::HashMap;
use p3_field::{AbstractField, PrimeField32};
use sphinx_core::air::EventLens;
use sphinx_core::stark::{Indexed, MachineRecord, PROOF_MAX_NUM_PVS};

use super::RecursionProgram;
use crate::air::Block;
use crate::cpu::{CpuChip, CpuEvent};
use crate::fri_fold::{FriFoldChip, FriFoldEvent};
use crate::memory::MemoryGlobalChip;
use crate::multi::MultiChip;
use crate::poseidon2::{Poseidon2Chip, Poseidon2Event};
use crate::poseidon2_wide::Poseidon2WideChip;
use crate::program::ProgramChip;
use crate::range_check::{RangeCheckChip, RangeCheckEvent};

#[derive(Default, Debug, Clone)]
pub struct ExecutionRecord<F: Default> {
    pub program: Arc<RecursionProgram<F>>,
    pub cpu_events: Vec<CpuEvent<F>>,
    pub poseidon2_events: Vec<Poseidon2Event<F>>,
    pub fri_fold_events: Vec<FriFoldEvent<F>>,
    pub range_check_events: HashMap<RangeCheckEvent, usize>,

    // (address, value)
    pub first_memory_record: Vec<(F, Block<F>)>,

    // (address, last_timestamp, last_value)
    pub last_memory_record: Vec<(F, F, Block<F>)>,

    /// The public values.
    pub public_values: Vec<F>,
}

impl<F: Default> ExecutionRecord<F> {
    pub fn add_range_check_events(&mut self, events: &[RangeCheckEvent]) {
        for event in events {
            *self.range_check_events.entry(*event).or_insert(0) += 1;
        }
    }
}

impl<F: PrimeField32> Indexed for ExecutionRecord<F> {
    fn index(&self) -> u32 {
        0
    }
}

impl<F: PrimeField32> MachineRecord for ExecutionRecord<F> {
    type Config = ();

    fn set_index(&mut self, _: u32) {}

    fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("cpu_events".to_string(), self.cpu_events.len());
        stats.insert("poseidon2_events".to_string(), self.poseidon2_events.len());
        stats.insert("fri_fold_events".to_string(), self.fri_fold_events.len());
        stats.insert(
            "range_check_events".to_string(),
            self.range_check_events.len(),
        );
        stats
    }

    // NOTE: This should be unused.
    fn append(&mut self, other: &mut Self) {
        self.cpu_events.append(&mut other.cpu_events);
        self.first_memory_record
            .append(&mut other.first_memory_record);
        self.last_memory_record
            .append(&mut other.last_memory_record);

        // Merge the range check lookups.
        for (range_check_event, count) in std::mem::take(&mut other.range_check_events) {
            *self
                .range_check_events
                .entry(range_check_event)
                .or_insert(0) += count;
        }
    }

    fn shard(self, _: &Self::Config) -> Vec<Self> {
        vec![self]
    }

    fn public_values<T: AbstractField>(&self) -> Vec<T> {
        let ret: [T; PROOF_MAX_NUM_PVS] = array::from_fn(|i| {
            if i < self.public_values.len() {
                T::from_canonical_u32(self.public_values[i].as_canonical_u32())
            } else {
                T::zero()
            }
        });

        ret.to_vec()
    }
}

impl<F: PrimeField32, const L: usize> EventLens<CpuChip<F, L>> for ExecutionRecord<F> {
    fn events(&self) -> <CpuChip<F, L> as sphinx_core::air::WithEvents<'_>>::Events {
        &self.cpu_events
    }
}

impl<F: PrimeField32, const DEGREE: usize> EventLens<FriFoldChip<F, DEGREE>>
    for ExecutionRecord<F>
{
    fn events(&self) -> <FriFoldChip<F, DEGREE> as sphinx_core::air::WithEvents<'_>>::Events {
        &self.fri_fold_events
    }
}

impl<F: PrimeField32> EventLens<Poseidon2Chip<F>> for ExecutionRecord<F> {
    fn events(&self) -> <Poseidon2Chip<F> as sphinx_core::air::WithEvents<'_>>::Events {
        &self.poseidon2_events
    }
}

impl<F: PrimeField32, const DEGREE: usize> EventLens<Poseidon2WideChip<F, DEGREE>>
    for ExecutionRecord<F>
{
    fn events(&self) -> <Poseidon2WideChip<F, DEGREE> as sphinx_core::air::WithEvents<'_>>::Events {
        &self.poseidon2_events
    }
}

impl<F: PrimeField32> EventLens<MemoryGlobalChip<F>> for ExecutionRecord<F> {
    fn events(&self) -> <MemoryGlobalChip<F> as sphinx_core::air::WithEvents<'_>>::Events {
        (&self.first_memory_record, &self.last_memory_record)
    }
}

impl<F: PrimeField32> EventLens<ProgramChip<F>> for ExecutionRecord<F> {
    fn events(&self) -> <ProgramChip<F> as sphinx_core::air::WithEvents<'_>>::Events {
        (&self.program.instructions, &self.cpu_events)
    }
}

impl<F: PrimeField32> EventLens<RangeCheckChip<F>> for ExecutionRecord<F> {
    fn events(&self) -> <RangeCheckChip<F> as sphinx_core::air::WithEvents<'_>>::Events {
        &self.range_check_events
    }
}

impl<F: PrimeField32, const DEGREE: usize> EventLens<MultiChip<F, DEGREE>> for ExecutionRecord<F> {
    fn events(&self) -> <MultiChip<F, DEGREE> as sphinx_core::air::WithEvents<'_>>::Events {
        (
            <Self as EventLens<FriFoldChip<F, DEGREE>>>::events(self),
            <Self as EventLens<Poseidon2Chip<F>>>::events(self),
        )
    }
}
