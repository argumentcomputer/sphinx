use p3_air::{
    AirBuilder, AirBuilderWithPublicValues, ExtensionBuilder, PairBuilder, PermutationAirBuilder,
};
use p3_matrix::{dense::RowMajorMatrixView, stack::VerticalPair};
use wp1_core::air::{EmptyMessageBuilder, MultiTableAirBuilder};
use wp1_recursion_compiler::{
    ir::{Builder, Config, Ext, Felt},
    prelude::SymbolicExt,
};

pub struct RecursiveVerifierConstraintFolder<'a, C: Config> {
    pub builder: &'a mut Builder<C>,
    pub preprocessed: VerticalPair<
        RowMajorMatrixView<'a, Ext<C::F, C::EF>>,
        RowMajorMatrixView<'a, Ext<C::F, C::EF>>,
    >,
    pub main: VerticalPair<
        RowMajorMatrixView<'a, Ext<C::F, C::EF>>,
        RowMajorMatrixView<'a, Ext<C::F, C::EF>>,
    >,
    pub perm: VerticalPair<
        RowMajorMatrixView<'a, Ext<C::F, C::EF>>,
        RowMajorMatrixView<'a, Ext<C::F, C::EF>>,
    >,
    pub perm_challenges: &'a [Ext<C::F, C::EF>],
    pub public_values: &'a [Felt<C::F>],
    pub cumulative_sum: Ext<C::F, C::EF>,
    pub is_first_row: Ext<C::F, C::EF>,
    pub is_last_row: Ext<C::F, C::EF>,
    pub is_transition: Ext<C::F, C::EF>,
    pub alpha: Ext<C::F, C::EF>,
    pub accumulator: Ext<C::F, C::EF>,
}

impl<'a, C: Config> AirBuilder for RecursiveVerifierConstraintFolder<'a, C> {
    type F = C::F;
    type Expr = SymbolicExt<C::F, C::EF>;
    type Var = Ext<C::F, C::EF>;
    type M = VerticalPair<
        RowMajorMatrixView<'a, Ext<C::F, C::EF>>,
        RowMajorMatrixView<'a, Ext<C::F, C::EF>>,
    >;

    fn main(&self) -> Self::M {
        self.main
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row.into()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row.into()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.is_transition.into()
        } else {
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: Self::Expr = x.into();
        self.builder
            .assign(&self.accumulator, self.accumulator * self.alpha);
        self.builder.assign(&self.accumulator, self.accumulator + x);
    }
}

impl<'a, C: Config> ExtensionBuilder for RecursiveVerifierConstraintFolder<'a, C> {
    type EF = C::EF;
    type ExprEF = SymbolicExt<C::F, C::EF>;
    type VarEF = Ext<C::F, C::EF>;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.assert_zero(x)
    }
}

impl<'a, C: Config> PermutationAirBuilder for RecursiveVerifierConstraintFolder<'a, C> {
    type MP = VerticalPair<RowMajorMatrixView<'a, Self::Var>, RowMajorMatrixView<'a, Self::Var>>;
    type RandomVar = Ext<C::F, C::EF>;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.perm_challenges
    }
}

impl<'a, C: Config> MultiTableAirBuilder for RecursiveVerifierConstraintFolder<'a, C> {
    type Sum = Self::Var;

    fn cumulative_sum(&self) -> Self::Sum {
        self.cumulative_sum
    }
}

impl<'a, C: Config> PairBuilder for RecursiveVerifierConstraintFolder<'a, C> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, C: Config> EmptyMessageBuilder for RecursiveVerifierConstraintFolder<'a, C> {}

impl<'a, C: Config> AirBuilderWithPublicValues for RecursiveVerifierConstraintFolder<'a, C> {
    type PublicVar = Felt<C::F>;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}
