use hashbrown::HashMap;
use sphinx_core::air::{EventLens, PublicValues, Word};
use sphinx_core::utils::SphinxCoreOpts;
use std::array;
use std::borrow::Borrow;
use std::sync::Arc;

use p3_field::{AbstractField, PrimeField32};
use sphinx_core::stark::{MachineRecord, PublicValued, PROOF_MAX_NUM_PVS};

use super::RecursionProgram;
use crate::air::Block;
use crate::cpu::{CpuChip, CpuEvent};
use crate::exp_reverse_bits::{ExpReverseBitsLenChip, ExpReverseBitsLenEvent};
use crate::fri_fold::{FriFoldChip, FriFoldEvent};
use crate::memory::MemoryGlobalChip;
use crate::multi::MultiChip;
use crate::poseidon2_wide::events::{Poseidon2CompressEvent, Poseidon2HashEvent};
use crate::poseidon2_wide::Poseidon2WideChip;
use crate::program::ProgramChip;
use crate::range_check::{RangeCheckChip, RangeCheckEvent};

#[derive(Default, Debug, Clone)]
pub struct ExecutionRecord<F: Default> {
    pub program: Arc<RecursionProgram<F>>,
    pub cpu_events: Vec<CpuEvent<F>>,
    pub poseidon2_compress_events: Vec<Poseidon2CompressEvent<F>>,
    pub poseidon2_hash_events: Vec<Poseidon2HashEvent<F>>,
    pub fri_fold_events: Vec<FriFoldEvent<F>>,
    pub range_check_events: HashMap<RangeCheckEvent, usize>,
    pub exp_reverse_bits_len_events: Vec<ExpReverseBitsLenEvent<F>>,
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

impl<FF: PrimeField32> PublicValued for ExecutionRecord<FF> {
    fn public_values<F: AbstractField + Clone>(&self) -> PublicValues<Word<F>, F> {
        let pvs: Vec<F> = MachineRecord::public_values::<F>(self);
        let pv: &PublicValues<Word<F>, F> = Borrow::borrow(&pvs[..]);
        pv.clone()
    }
}

impl<F: PrimeField32> MachineRecord for ExecutionRecord<F> {
    type Config = SphinxCoreOpts;

    fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("cpu_events".to_string(), self.cpu_events.len());
        stats.insert(
            "poseidon2_events".to_string(),
            self.poseidon2_compress_events.len(),
        );
        stats.insert(
            "poseidon2_events".to_string(),
            self.poseidon2_hash_events.len(),
        );
        stats.insert("fri_fold_events".to_string(), self.fri_fold_events.len());
        stats.insert(
            "range_check_events".to_string(),
            self.range_check_events.len(),
        );
        stats.insert(
            "exp_reverse_bits_len_events".to_string(),
            self.exp_reverse_bits_len_events.len(),
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

impl<F: PrimeField32, const DEGREE: usize> EventLens<Poseidon2WideChip<F, DEGREE>>
    for ExecutionRecord<F>
{
    fn events(&self) -> <Poseidon2WideChip<F, DEGREE> as sphinx_core::air::WithEvents<'_>>::Events {
        (&self.poseidon2_hash_events, &self.poseidon2_compress_events)
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
            <Self as EventLens<Poseidon2WideChip<F, DEGREE>>>::events(self),
        )
    }
}

impl<F: PrimeField32, const DEGREE: usize> EventLens<ExpReverseBitsLenChip<F, DEGREE>>
    for ExecutionRecord<F>
{
    fn events(
        &self,
    ) -> <ExpReverseBitsLenChip<F, DEGREE> as sphinx_core::air::WithEvents<'_>>::Events {
        &self.exp_reverse_bits_len_events
    }
}
