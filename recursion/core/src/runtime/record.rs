use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use p3_field::{AbstractField, PrimeField32};
use sphinx_core::air::{EventLens, EventMutLens, WithEvents};
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
    pub range_check_events: BTreeMap<RangeCheckEvent, usize>,

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
        let mut ret = self
            .public_values
            .iter()
            .map(|x| T::from_canonical_u32(x.as_canonical_u32()))
            .collect::<Vec<_>>();

        // Pad the public values to the correct number of public values, in case not all are used.
        ret.resize(PROOF_MAX_NUM_PVS, T::zero());

        ret
    }
}

impl<F: PrimeField32> EventLens<CpuChip<F>> for ExecutionRecord<F> {
    fn events(&self) -> <CpuChip<F> as WithEvents<'_>>::InputEvents {
        &self.cpu_events
    }
}

impl<F: PrimeField32, const DEGREE: usize> EventLens<FriFoldChip<F, DEGREE>>
    for ExecutionRecord<F>
{
    fn events(&self) -> <FriFoldChip<F, DEGREE> as WithEvents<'_>>::InputEvents {
        &self.fri_fold_events
    }
}

impl<F: PrimeField32> EventLens<Poseidon2Chip<F>> for ExecutionRecord<F> {
    fn events(&self) -> <Poseidon2Chip<F> as WithEvents<'_>>::InputEvents {
        &self.poseidon2_events
    }
}

impl<F: PrimeField32, const DEGREE: usize> EventLens<Poseidon2WideChip<F, DEGREE>>
    for ExecutionRecord<F>
{
    fn events(&self) -> <Poseidon2WideChip<F, DEGREE> as WithEvents<'_>>::InputEvents {
        &self.poseidon2_events
    }
}

impl<F: PrimeField32> EventLens<MemoryGlobalChip<F>> for ExecutionRecord<F> {
    fn events(&self) -> <MemoryGlobalChip<F> as WithEvents<'_>>::InputEvents {
        (&self.first_memory_record, &self.last_memory_record)
    }
}

impl<F: PrimeField32> EventLens<ProgramChip<F>> for ExecutionRecord<F> {
    fn events(&self) -> <ProgramChip<F> as WithEvents<'_>>::InputEvents {
        (&self.program.instructions, &self.cpu_events)
    }
}

impl<F: PrimeField32> EventLens<RangeCheckChip<F>> for ExecutionRecord<F> {
    fn events(&self) -> <RangeCheckChip<F> as WithEvents<'_>>::InputEvents {
        &self.range_check_events
    }
}

impl<F: PrimeField32, const DEGREE: usize> EventLens<MultiChip<F, DEGREE>> for ExecutionRecord<F> {
    fn events(&self) -> <MultiChip<F, DEGREE> as WithEvents<'_>>::InputEvents {
        (
            <Self as EventLens<FriFoldChip<F, DEGREE>>>::events(self),
            <Self as EventLens<Poseidon2Chip<F>>>::events(self),
        )
    }
}

// For a recursive machine chip, there are no dependencies since we manage them in the runtime.
// The output events are always empty.
impl<F: PrimeField32, Chip: for<'a> WithEvents<'a, OutputEvents = &'a ()>> EventMutLens<Chip>
    for ExecutionRecord<F>
{
    fn add_events(&mut self, _events: <Chip as WithEvents<'_>>::OutputEvents) {}
}
