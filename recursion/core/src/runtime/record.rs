use std::{collections::HashMap, sync::Arc};

use p3_field::{AbstractField, PrimeField32};
use wp1_core::stark::{MachineRecord, PROOF_MAX_NUM_PVS};

use super::RecursionProgram;
use crate::air::Block;
use crate::cpu::CpuEvent;
use crate::fri_fold::FriFoldEvent;
use crate::poseidon2::Poseidon2Event;

#[derive(Default, Debug, Clone)]
pub struct ExecutionRecord<F: Default> {
    pub program: Arc<RecursionProgram<F>>,
    pub cpu_events: Vec<CpuEvent<F>>,
    pub poseidon2_events: Vec<Poseidon2Event<F>>,
    pub fri_fold_events: Vec<FriFoldEvent<F>>,

    // (address)
    pub first_memory_record: Vec<F>,

    // (address, last_timestamp, last_value)
    pub last_memory_record: Vec<(F, F, Block<F>)>,

    /// The public values.
    pub public_values: Vec<F>,
}

impl<F: PrimeField32> MachineRecord for ExecutionRecord<F> {
    type Config = ();

    fn index(&self) -> u32 {
        0
    }

    fn set_index(&mut self, _: u32) {}

    fn stats(&self) -> HashMap<String, usize> {
        HashMap::new()
    }

    fn append(&mut self, other: &mut Self) {
        self.cpu_events.append(&mut other.cpu_events);
        self.first_memory_record
            .append(&mut other.first_memory_record);
        self.last_memory_record
            .append(&mut other.last_memory_record);
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
