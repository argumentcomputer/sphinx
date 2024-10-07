use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use std::array;
use std::marker::PhantomData;

use p3_air::{Air, AirBuilder};
use p3_air::{AirBuilderWithPublicValues, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sphinx_derive::AlignedBorrow;

use super::MemoryInitializeFinalizeEvent;
use crate::air::{AirInteraction, BaseAirBuilder, EventLens, PublicValues, WithEvents, Word};
use crate::air::{MachineAir, SPHINX_PROOF_NUM_PV_ELTS};
use crate::operations::{AssertLtColsBits, BabyBearBitDecomposition, IsZeroOperation};
use crate::runtime::{ExecutionRecord, Program};
use crate::utils::pad_to_power_of_two;

/// The type of memory chip that is being initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryChipType {
    Initialize,
    Finalize,
}

/// A memory chip that can initialize or finalize values in memory.
pub struct MemoryChip<F> {
    pub kind: MemoryChipType,
    _marker: PhantomData<F>,
}

impl<F> MemoryChip<F> {
    /// Creates a new memory chip with a certain type.
    pub fn new(kind: MemoryChipType) -> Self {
        Self {
            kind,
            _marker: PhantomData,
        }
    }
}

impl<F: Send + Sync> BaseAir<F> for MemoryChip<F> {
    fn width(&self) -> usize {
        NUM_MEMORY_INIT_COLS
    }
}

impl<'a, F: 'a> WithEvents<'a> for MemoryChip<F> {
    type Events = (
        // initialize events
        &'a [MemoryInitializeFinalizeEvent],
        // finalize events
        &'a [MemoryInitializeFinalizeEvent],
        // the public values
        PublicValues<Word<F>, F>,
    );
}

impl<F: PrimeField32> MachineAir<F> for MemoryChip<F> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        match self.kind {
            MemoryChipType::Initialize => "MemoryInit".to_string(),
            MemoryChipType::Finalize => "MemoryFinalize".to_string(),
        }
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let (mem_init_events, mem_final_events, pv) = input.events();

        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => mem_init_events.to_vec(),
            MemoryChipType::Finalize => mem_final_events.to_vec(),
        };

        let previous_addr_bits = match self.kind {
            MemoryChipType::Initialize => pv.previous_init_addr_bits.map(|f| f.as_canonical_u32()),
            MemoryChipType::Finalize => {
                pv.previous_finalize_addr_bits.map(|f| f.as_canonical_u32())
            }
        };

        memory_events.sort_by_key(|event| event.addr);
        let rows: Vec<[F; NUM_MEMORY_INIT_COLS]> = (0..memory_events.len()) // OPT: change this to par_iter
            .map(|i| {
                let MemoryInitializeFinalizeEvent {
                    addr,
                    value,
                    shard,
                    timestamp,
                    used,
                } = memory_events[i];

                let mut row = [F::zero(); NUM_MEMORY_INIT_COLS];
                let cols: &mut MemoryInitCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr = F::from_canonical_u32(addr);
                cols.addr_bits.populate(addr);
                cols.shard = F::from_canonical_u32(shard);
                cols.timestamp = F::from_canonical_u32(timestamp);
                cols.value = array::from_fn(|i| F::from_canonical_u32((value >> i) & 1));
                cols.is_real = F::from_canonical_u32(used);

                if i == 0 {
                    let prev_addr = previous_addr_bits
                        .iter()
                        .enumerate()
                        .map(|(j, bit)| bit * (1 << j))
                        .sum::<u32>();
                    cols.is_prev_addr_zero.populate(prev_addr);
                    cols.is_first_comp = F::from_bool(prev_addr != 0);
                    if prev_addr != 0 {
                        debug_assert!(prev_addr < addr, "prev_addr {} < addr {}", prev_addr, addr);
                        let addr_bits: [_; 32] = array::from_fn(|i| (addr >> i) & 1);
                        cols.lt_cols.populate(&previous_addr_bits, &addr_bits);
                    }
                }

                if i != 0 {
                    let prev_is_real = memory_events[i - 1].used;
                    cols.is_next_comp = F::from_canonical_u32(prev_is_real);
                    let previous_addr = memory_events[i - 1].addr;
                    assert_ne!(previous_addr, addr);

                    let addr_bits: [_; 32] = array::from_fn(|i| (addr >> i) & 1);
                    let prev_addr_bits: [_; 32] = array::from_fn(|i| (previous_addr >> i) & 1);
                    cols.lt_cols.populate(&prev_addr_bits, &addr_bits);
                }

                if i == memory_events.len() - 1 {
                    cols.is_last_addr = F::one();
                }

                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_INIT_COLS,
        );

        pad_to_power_of_two::<NUM_MEMORY_INIT_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match self.kind {
            MemoryChipType::Initialize => !shard.memory_initialize_events.is_empty(),
            MemoryChipType::Finalize => !shard.memory_finalize_events.is_empty(),
        }
    }
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryInitCols<T> {
    /// The shard number of the memory access.
    pub shard: T,

    /// The timestamp of the memory access.
    pub timestamp: T,

    /// The address of the memory access.
    pub addr: T,

    /// Comparison assertions for address to be strictly increasing.
    pub lt_cols: AssertLtColsBits<T, 32>,

    /// A bit decomposition of `addr`.
    pub addr_bits: BabyBearBitDecomposition<T>,

    /// The value of the memory access.
    pub value: [T; 32],

    /// Whether the memory access is a real access.
    pub is_real: T,

    /// Whether or not we are making the assertion `addr < addr_next`.
    pub is_next_comp: T,

    /// A witness to assert whether or not we the previous address is zero.
    pub is_prev_addr_zero: IsZeroOperation<T>,

    /// Auxilary column, equal to `(1 - is_prev_addr_zero.result) * is_first_row`.
    pub is_first_comp: T,

    /// A flag to inidicate the last non-padded address. An auxiliary column needed for degree 3.
    pub is_last_addr: T,
}

pub(crate) const NUM_MEMORY_INIT_COLS: usize = size_of::<MemoryInitCols<u8>>();

impl<AB> Air<AB> for MemoryChip<AB::F>
where
    AB: AirBuilderWithPublicValues + BaseAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryInitCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &MemoryInitCols<AB::Var> = (*next).borrow();

        builder.assert_bool(local.is_real);
        for i in 0..32 {
            builder.assert_bool(local.value[i]);
        }

        let mut byte1 = AB::Expr::zero();
        let mut byte2 = AB::Expr::zero();
        let mut byte3 = AB::Expr::zero();
        let mut byte4 = AB::Expr::zero();
        for i in 0..8 {
            byte1 += local.value[i].into() * AB::F::from_canonical_u8(1 << i);
            byte2 += local.value[i + 8].into() * AB::F::from_canonical_u8(1 << i);
            byte3 += local.value[i + 16].into() * AB::F::from_canonical_u8(1 << i);
            byte4 += local.value[i + 24].into() * AB::F::from_canonical_u8(1 << i);
        }
        let value = [byte1, byte2, byte3, byte4];

        if self.kind == MemoryChipType::Initialize {
            let mut values = vec![AB::Expr::zero(), AB::Expr::zero(), local.addr.into()];
            values.extend(value.map(Into::into));
            builder.receive(AirInteraction::new(
                values,
                local.is_real.into(),
                crate::lookup::InteractionKind::Memory,
            ));
        } else {
            let mut values = vec![
                local.shard.into(),
                local.timestamp.into(),
                local.addr.into(),
            ];
            values.extend(value);
            builder.send(AirInteraction::new(
                values,
                local.is_real.into(),
                crate::lookup::InteractionKind::Memory,
            ));
        }

        // Canonically decompose the address into bits so we can do comparisons.
        BabyBearBitDecomposition::<AB::F>::range_check(
            builder,
            local.addr,
            local.addr_bits,
            local.is_real.into(),
        );

        // Assertion for increasing address. We need to make two types of less-than assertions,
        // first we ned to assert that the addr < addr' when the next row is real. Then we need to
        // make assertions with regards to public values.
        //
        // If the chip is a `MemoryInit`:
        // - In the first row, we need to assert that previous_init_addr < addr.
        // - In the last real row, we need to assert that addr = last_init_addr.
        //
        // If the chip is a `MemoryFinalize`:
        // - In the first row, we need to assert that previous_finalize_addr < addr.
        // - In the last real row, we need to assert that addr = last_finalize_addr.

        // Assert that addr < addr' when the next row is real.
        builder
            .when_transition()
            .assert_eq(next.is_next_comp, next.is_real);
        next.lt_cols.eval(
            builder,
            &local.addr_bits.bits,
            &next.addr_bits.bits,
            &next.is_next_comp,
        );

        // Assert that the real rows are all padded to the top.
        builder
            .when_transition()
            .when_not(local.is_real)
            .assert_zero(next.is_real);

        // Make assertions for the initial comparison.

        // We want to constrain that the `adrr` in the first row is larger than the previous
        // initialized/finalized address, unless the previous address is zero. Since the previous
        // address is either zero or constrained by a different shard, we know it's an element of
        // the field, so we can get an element from the bit decomposition with no concern for
        // overflow.

        let local_addr_bits = local.addr_bits.bits;

        let public_values_array: [AB::Expr; SPHINX_PROOF_NUM_PV_ELTS] =
            array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<AB::Expr>, AB::Expr> =
            public_values_array.as_slice().borrow();

        let prev_addr_bits = match self.kind {
            MemoryChipType::Initialize => &public_values.previous_init_addr_bits,
            MemoryChipType::Finalize => &public_values.previous_finalize_addr_bits,
        };

        // Since the previous address is either zero or constrained by a different shard, we know
        // it's an element of the field, so we can get an element from the bit decomposition with
        // no concern for overflow.
        let prev_addr = prev_addr_bits
            .iter()
            .enumerate()
            .map(|(i, bit)| bit.clone() * AB::F::from_wrapped_u32(1 << i))
            .sum::<AB::Expr>();

        // Constrain the is_prev_addr_zero operation only in the first row.
        let is_first_row = builder.is_first_row();
        IsZeroOperation::<AB::F>::eval(builder, prev_addr, local.is_prev_addr_zero, is_first_row);

        // Constrain the is_first_comp column.
        builder.assert_bool(local.is_first_comp);
        builder.when_first_row().assert_eq(
            local.is_first_comp,
            AB::Expr::one() - local.is_prev_addr_zero.result,
        );

        // Constrain the inequality assertion in the first row.
        local.lt_cols.eval(
            builder,
            prev_addr_bits,
            &local_addr_bits,
            &local.is_first_comp,
        );

        // Make assertions for specific types of memory chips.

        if self.kind == MemoryChipType::Initialize {
            builder
                .when(local.is_real)
                .assert_eq(local.timestamp, AB::F::one());
        }

        // Constraints related to register %x0.

        // Register %x0 should always be 0. See 2.6 Load and Store Instruction on
        // P.18 of the RISC-V spec.  To ensure that, we will constain that the value is zero
        // whenever the `is_first_comp` flag is set to to zero as well. This guarantees that the
        // presence of this flag asserts the initialization/finalization of %x0 to zero.
        //
        // **Remark**: it is up to the verifier to ensure that this flag is set to zero exactly
        // once, this can be constrained by the public values setting `previous_init_addr_bits` or
        // `previous_finalize_addr_bits` to zero.
        for i in 0..32 {
            builder
                .when_first_row()
                .when_not(local.is_first_comp)
                .assert_zero(local.value[i]);
        }

        // Make assertions for the final value. We need to connect the final valid address to the
        // correspinding `last_addr` value.
        let last_addr_bits = match self.kind {
            MemoryChipType::Initialize => &public_values.last_init_addr_bits,
            MemoryChipType::Finalize => &public_values.last_finalize_addr_bits,
        };
        // The last address is either:
        // - It's the last row and `is_real` is set to one.
        // - The flag `is_real` is set to one and the next `is_real` is set to zero.
        for (local_bit, pub_bit) in local.addr_bits.bits.iter().zip(last_addr_bits.iter()) {
            builder
                .when_last_row()
                .when(local.is_real)
                .assert_eq(*local_bit, pub_bit.clone());
            builder
                .when_transition()
                .when(local.is_last_addr)
                .assert_eq(*local_bit, pub_bit.clone());
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::lookup::{debug_interactions_with_all_chips, InteractionKind};
    use crate::runtime::tests::simple_program;
    use crate::runtime::Runtime;
    use crate::stark::RiscvAir;
    use crate::syscall::precompiles::sha256::extend_tests::sha_extend_program;
    use crate::utils::{setup_logger, BabyBearPoseidon2, SphinxCoreOpts};
    use p3_baby_bear::BabyBear;

    #[test]
    fn test_memory_generate_trace() {
        let program = simple_program();
        let mut runtime = Runtime::new(program, SphinxCoreOpts::default());
        runtime.run().unwrap();
        let shard = runtime.record.clone();

        let chip: MemoryChip<BabyBear> = MemoryChip::new(MemoryChipType::Initialize);

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        let chip: MemoryChip<BabyBear> = MemoryChip::new(MemoryChipType::Finalize);
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        for mem_event in shard.memory_finalize_events {
            println!("{:?}", mem_event);
        }
    }

    #[test]
    fn test_memory_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Runtime::new(program, SphinxCoreOpts::default());
        runtime.run().unwrap();
        let machine: crate::stark::StarkMachine<BabyBearPoseidon2, RiscvAir<BabyBear>> =
            RiscvAir::machine(BabyBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let opts = SphinxCoreOpts::default();
        machine.generate_dependencies(&mut runtime.records, &opts);

        let shards = runtime.records;
        assert_eq!(shards.len(), 2);
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards,
            &[InteractionKind::Memory],
        );
    }

    #[test]
    fn test_byte_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Runtime::new(program, SphinxCoreOpts::default());
        runtime.run().unwrap();
        let machine = RiscvAir::machine(BabyBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let opts = SphinxCoreOpts::default();
        machine.generate_dependencies(&mut runtime.records, &opts);

        let shards = runtime.records;
        assert_eq!(shards.len(), 2);
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards,
            &[InteractionKind::Byte],
        );
    }
}
