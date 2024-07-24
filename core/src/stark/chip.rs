use std::hash::Hash;

use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::{ExtensionField, Field, PrimeField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{get_max_constraint_degree, SymbolicAirBuilder};
use p3_util::log2_ceil_usize;

use crate::{
    air::{BaseAirBuilder, MachineAir, MultiTableAirBuilder},
    lookup::{Interaction, InteractionBuilder, InteractionKind},
};

use super::{
    eval_permutation_constraints, generate_permutation_trace, permutation_trace_width,
    PROOF_MAX_NUM_PVS,
};

/// An Air that encodes lookups based on interactions.
pub struct Chip<F: Field, A> {
    /// The underlying AIR of the chip for constraint evaluation.
    air: A,
    /// The interactions that the chip sends.
    sends: Vec<Interaction<F>>,
    /// The interactions that the chip receives.
    receives: Vec<Interaction<F>>,
    /// The relative log degree of the quotient polynomial, i.e. `log2(max_constraint_degree - 1)`.
    log_quotient_degree: usize,
}

impl<F: Field, A> AsRef<A> for Chip<F, A> {
    fn as_ref(&self) -> &A {
        &self.air
    }
}

impl<F: Field, A> Chip<F, A> {
    /// The send interactions of the chip.
    pub fn sends(&self) -> &[Interaction<F>] {
        &self.sends
    }

    /// The receive interactions of the chip.
    pub fn receives(&self) -> &[Interaction<F>] {
        &self.receives
    }

    /// The relative log degree of the quotient polynomial, i.e. `log2(max_constraint_degree - 1)`.
    pub const fn log_quotient_degree(&self) -> usize {
        self.log_quotient_degree
    }
}

impl<F: PrimeField32, A: MachineAir<F>> Chip<F, A> {
    /// Returns whether the given chip is included in the execution record of the shard.
    pub fn included(&self, shard: &A::Record) -> bool {
        self.air.included(shard)
    }
}

impl<F, A> Chip<F, A>
where
    F: Field,
{
    /// Records the interactions and constraint degree from the air and crates a new chip.
    pub fn new(air: A) -> Self
    where
        A: MachineAir<F> + Air<InteractionBuilder<F>> + Air<SymbolicAirBuilder<F>>,
    {
        let mut builder = InteractionBuilder::new(air.preprocessed_width(), air.width());
        air.eval(&mut builder);
        let (sends, receives) = builder.interactions();

        let nb_byte_sends = sends
            .iter()
            .filter(|s| s.kind == InteractionKind::Byte)
            .count();
        let nb_byte_receives = receives
            .iter()
            .filter(|r| r.kind == InteractionKind::Byte)
            .count();
        tracing::debug!(
            "chip {} has {} byte interactions",
            air.name(),
            nb_byte_sends + nb_byte_receives
        );

        let mut max_constraint_degree =
            get_max_constraint_degree(&air, air.preprocessed_width(), PROOF_MAX_NUM_PVS);

        if !sends.is_empty() || !receives.is_empty() {
            max_constraint_degree = max_constraint_degree.max(3);
        }
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);

        Self {
            air,
            sends,
            receives,
            log_quotient_degree,
        }
    }

    #[inline]
    pub fn num_interactions(&self) -> usize {
        self.sends.len() + self.receives.len()
    }

    #[inline]
    pub fn num_sends_by_kind(&self, kind: InteractionKind) -> usize {
        self.sends.iter().filter(|i| i.kind == kind).count()
    }

    #[inline]
    pub fn num_receives_by_kind(&self, kind: InteractionKind) -> usize {
        self.receives.iter().filter(|i| i.kind == kind).count()
    }

    pub fn generate_permutation_trace<EF: ExtensionField<F>>(
        &self,
        preprocessed: Option<&RowMajorMatrix<F>>,
        main: &RowMajorMatrix<F>,
        random_elements: &[EF],
    ) -> RowMajorMatrix<EF>
    where
        F: PrimeField,
    {
        let batch_size = self.logup_batch_size();
        generate_permutation_trace(
            &self.sends,
            &self.receives,
            preprocessed,
            main,
            random_elements,
            batch_size,
        )
    }

    #[inline]
    pub fn permutation_width(&self) -> usize {
        permutation_trace_width(
            self.sends().len() + self.receives().len(),
            self.logup_batch_size(),
        )
    }

    #[inline]
    pub const fn quotient_width(&self) -> usize {
        1 << self.log_quotient_degree
    }

    #[inline]
    pub const fn logup_batch_size(&self) -> usize {
        1 << self.log_quotient_degree
    }
}

impl<F, A> BaseAir<F> for Chip<F, A>
where
    F: Field,
    A: BaseAir<F>,
{
    fn width(&self) -> usize {
        self.air.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        panic!("Chip should not use the `BaseAir` method, but the `MachineAir` method.")
    }
}

// Implement AIR directly on Chip, evaluating both execution and permutation constraints.
impl<F, A, AB> Air<AB> for Chip<F, A>
where
    F: Field,
    A: Air<AB>,
    AB: BaseAirBuilder<F = F> + MultiTableAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Evaluate the execution trace constraints.
        self.air.eval(builder);
        // Evaluate permutation constraints.
        let batch_size = self.logup_batch_size();
        eval_permutation_constraints(&self.sends, &self.receives, batch_size, builder);
    }
}

impl<F, A> PartialEq for Chip<F, A>
where
    F: Field,
    A: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.air == other.air
    }
}

impl<F, A: Eq> Eq for Chip<F, A> where F: Field + Eq {}

impl<F, A> Hash for Chip<F, A>
where
    F: Field,
    A: Hash,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.air.hash(state);
    }
}
