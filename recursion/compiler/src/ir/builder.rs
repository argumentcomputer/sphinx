use std::{iter::Zip, vec::IntoIter};

use backtrace::Backtrace;
use p3_field::AbstractField;
use wp1_recursion_core::runtime::PV_BUFFER_MAX_SIZE;

use super::{
    Array, Config, DslIr, Ext, Felt, FromConstant, SymbolicExt, SymbolicFelt, SymbolicUsize,
    SymbolicVar, Usize, Var, Variable,
};

/// TracedVec is a Vec wrapper that records a trace whenever an element is pushed. When extending
/// from another TracedVec, the traces are copied over.
#[derive(Debug, Clone)]
pub struct TracedVec<T> {
    pub vec: Vec<T>,
    pub traces: Vec<Option<Backtrace>>,
}

impl<T> Default for TracedVec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> From<Vec<T>> for TracedVec<T> {
    fn from(vec: Vec<T>) -> Self {
        let len = vec.len();
        Self {
            vec,
            traces: vec![None; len],
        }
    }
}

impl<T> TracedVec<T> {
    pub fn new() -> Self {
        Self {
            vec: Vec::new(),
            traces: Vec::new(),
        }
    }

    pub fn push(&mut self, value: T) {
        self.vec.push(value);
        match std::env::var("SP1_DEBUG") {
            Ok(_) => {
                self.traces.push(Some(Backtrace::new_unresolved()));
            }
            Err(_) => {
                self.traces.push(None);
            }
        };
    }

    pub fn extend<I: IntoIterator<Item = (T, Option<Backtrace>)>>(&mut self, iter: I) {
        let iter = iter.into_iter();
        let len = iter.size_hint().0;
        self.vec.reserve(len);
        self.traces.reserve(len);
        for (value, trace) in iter {
            self.vec.push(value);
            self.traces.push(trace);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }
}

impl<T> IntoIterator for TracedVec<T> {
    type Item = (T, Option<Backtrace>);
    type IntoIter = Zip<IntoIter<T>, IntoIter<Option<Backtrace>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.vec.into_iter().zip(self.traces)
    }
}

/// A builder for the DSL.
///
/// Can compile to both assembly and a set of constraints.
#[derive(Debug, Clone, Default)]
pub struct Builder<C: Config> {
    pub(crate) felt_count: u32,
    pub(crate) ext_count: u32,
    pub(crate) var_count: u32,
    pub operations: TracedVec<DslIr<C>>,
    pub nb_public_values: Option<Var<C::N>>,
    pub public_values_buffer: Option<Array<C, Felt<C::F>>>,
    pub witness_var_count: u32,
    pub witness_felt_count: u32,
    pub witness_ext_count: u32,
    pub debug: bool,
    pub po2_table: Option<Array<C, Var<C::N>>>,
}

impl<C: Config> Builder<C> {
    /// Creates a new builder with a given number of counts for each type.
    pub fn new(var_count: u32, felt_count: u32, ext_count: u32) -> Self {
        Self {
            felt_count,
            ext_count,
            var_count,
            witness_var_count: 0,
            witness_felt_count: 0,
            witness_ext_count: 0,
            operations: Default::default(),
            nb_public_values: None,
            public_values_buffer: None,
            debug: false,
            po2_table: None,
        }
    }

    /// Pushes an operation to the builder.
    pub fn push(&mut self, op: DslIr<C>) {
        self.operations.push(op);
    }

    /// Creates an uninitialized variable.
    pub fn uninit<V: Variable<C>>(&mut self) -> V {
        V::uninit(self)
    }

    /// Evaluates an expression and returns a variable.
    pub fn eval<V: Variable<C>, E: Into<V::Expression>>(&mut self, expr: E) -> V {
        let dst = V::uninit(self);
        dst.assign(expr.into(), self);
        dst
    }

    /// Evaluates a constant expression and returns a variable.
    pub fn constant<V: FromConstant<C>>(&mut self, value: V::Constant) -> V {
        V::constant(value, self)
    }

    /// Assigns an expression to a variable.
    pub fn assign<V: Variable<C>, E: Into<V::Expression>>(&mut self, dst: &V, expr: E) {
        dst.assign(expr.into(), self);
    }

    /// Asserts that two expressions are equal.
    pub fn assert_eq<V: Variable<C>>(
        &mut self,
        lhs: impl Into<V::Expression>,
        rhs: impl Into<V::Expression>,
    ) {
        V::assert_eq(lhs, rhs, self);
    }

    /// Asserts that two expressions are not equal.
    pub fn assert_ne<V: Variable<C>>(
        &mut self,
        lhs: impl Into<V::Expression>,
        rhs: impl Into<V::Expression>,
    ) {
        V::assert_ne(lhs, rhs, self);
    }

    /// Assert that two vars are equal.
    pub fn assert_var_eq<LhsExpr: Into<SymbolicVar<C::N>>, RhsExpr: Into<SymbolicVar<C::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Var<C::N>>(lhs, rhs);
    }

    /// Assert that two vars are not equal.
    pub fn assert_var_ne<LhsExpr: Into<SymbolicVar<C::N>>, RhsExpr: Into<SymbolicVar<C::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Var<C::N>>(lhs, rhs);
    }

    /// Assert that two felts are equal.
    pub fn assert_felt_eq<LhsExpr: Into<SymbolicFelt<C::F>>, RhsExpr: Into<SymbolicFelt<C::F>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Felt<C::F>>(lhs, rhs);
    }

    /// Assert that two felts are not equal.
    pub fn assert_felt_ne<LhsExpr: Into<SymbolicFelt<C::F>>, RhsExpr: Into<SymbolicFelt<C::F>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Felt<C::F>>(lhs, rhs);
    }

    /// Assert that two usizes are equal.
    pub fn assert_usize_eq<
        LhsExpr: Into<SymbolicUsize<C::N>>,
        RhsExpr: Into<SymbolicUsize<C::N>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Usize<C::N>>(lhs, rhs);
    }

    /// Assert that two usizes are not equal.
    pub fn assert_usize_ne(&mut self, lhs: SymbolicUsize<C::N>, rhs: SymbolicUsize<C::N>) {
        self.assert_ne::<Usize<C::N>>(lhs, rhs);
    }

    /// Assert that two exts are equal.
    pub fn assert_ext_eq<
        LhsExpr: Into<SymbolicExt<C::F, C::EF>>,
        RhsExpr: Into<SymbolicExt<C::F, C::EF>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Ext<C::F, C::EF>>(lhs, rhs);
    }

    /// Assert that two exts are not equal.
    pub fn assert_ext_ne<
        LhsExpr: Into<SymbolicExt<C::F, C::EF>>,
        RhsExpr: Into<SymbolicExt<C::F, C::EF>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Ext<C::F, C::EF>>(lhs, rhs);
    }

    pub fn lt(&mut self, lhs: Var<C::N>, rhs: Var<C::N>) -> Var<C::N> {
        let result = self.uninit();
        self.operations.push(DslIr::LessThan(result, lhs, rhs));
        result
    }

    /// Evaluate a block of operations if two expressions are equal.
    pub fn if_eq<LhsExpr: Into<SymbolicVar<C::N>>, RhsExpr: Into<SymbolicVar<C::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) -> IfBuilder<'_, C> {
        IfBuilder {
            lhs: lhs.into(),
            rhs: rhs.into(),
            is_eq: true,
            builder: self,
        }
    }

    /// Evaluate a block of operations if two expressions are not equal.
    pub fn if_ne<LhsExpr: Into<SymbolicVar<C::N>>, RhsExpr: Into<SymbolicVar<C::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) -> IfBuilder<'_, C> {
        IfBuilder {
            lhs: lhs.into(),
            rhs: rhs.into(),
            is_eq: false,
            builder: self,
        }
    }

    /// Evaluate a block of operations over a range from start to end.
    pub fn range(
        &mut self,
        start: impl Into<Usize<C::N>>,
        end: impl Into<Usize<C::N>>,
    ) -> RangeBuilder<'_, C> {
        RangeBuilder {
            start: start.into(),
            end: end.into(),
            builder: self,
            step_size: 1,
        }
    }

    /// Break out of a loop.
    pub fn break_loop(&mut self) {
        self.operations.push(DslIr::Break);
    }

    pub fn print_debug(&mut self, val: usize) {
        let constant = self.eval(C::N::from_canonical_usize(val));
        self.print_v(constant);
    }

    /// Print a variable.
    pub fn print_v(&mut self, dst: Var<C::N>) {
        self.operations.push(DslIr::PrintV(dst));
    }

    /// Print a felt.
    pub fn print_f(&mut self, dst: Felt<C::F>) {
        self.operations.push(DslIr::PrintF(dst));
    }

    /// Print an ext.
    pub fn print_e(&mut self, dst: Ext<C::F, C::EF>) {
        self.operations.push(DslIr::PrintE(dst));
    }

    /// Hint the length of the next vector of variables.
    pub fn hint_len(&mut self) -> Var<C::N> {
        let len = self.uninit();
        self.operations.push(DslIr::HintLen(len));
        len
    }

    /// Hint a single variable.
    pub fn hint_var(&mut self) -> Var<C::N> {
        let len = self.hint_len();
        let arr = self.dyn_array(len);
        self.operations.push(DslIr::HintVars(arr.clone()));
        self.get(&arr, 0)
    }

    /// Hint a single felt.
    pub fn hint_felt(&mut self) -> Felt<C::F> {
        let len = self.hint_len();
        let arr = self.dyn_array(len);
        self.operations.push(DslIr::HintFelts(arr.clone()));
        self.get(&arr, 0)
    }

    /// Hint a single ext.
    pub fn hint_ext(&mut self) -> Ext<C::F, C::EF> {
        let len = self.hint_len();
        let arr = self.dyn_array(len);
        self.operations.push(DslIr::HintExts(arr.clone()));
        self.get(&arr, 0)
    }

    /// Hint a vector of variables.
    pub fn hint_vars(&mut self) -> Array<C, Var<C::N>> {
        let len = self.hint_len();
        let arr = self.dyn_array(len);
        self.operations.push(DslIr::HintVars(arr.clone()));
        arr
    }

    /// Hint a vector of felts.
    pub fn hint_felts(&mut self) -> Array<C, Felt<C::F>> {
        let len = self.hint_len();
        let arr = self.dyn_array(len);
        self.operations.push(DslIr::HintFelts(arr.clone()));
        arr
    }

    /// Hint a vector of exts.
    pub fn hint_exts(&mut self) -> Array<C, Ext<C::F, C::EF>> {
        let len = self.hint_len();
        let arr = self.dyn_array(len);
        self.operations.push(DslIr::HintExts(arr.clone()));
        arr
    }

    pub fn witness_var(&mut self) -> Var<C::N> {
        let witness = self.uninit();
        self.operations
            .push(DslIr::WitnessVar(witness, self.witness_var_count));
        self.witness_var_count += 1;
        witness
    }

    pub fn witness_felt(&mut self) -> Felt<C::F> {
        let witness = self.uninit();
        self.operations
            .push(DslIr::WitnessFelt(witness, self.witness_felt_count));
        self.witness_felt_count += 1;
        witness
    }

    pub fn witness_ext(&mut self) -> Ext<C::F, C::EF> {
        let witness = self.uninit();
        self.operations
            .push(DslIr::WitnessExt(witness, self.witness_ext_count));
        self.witness_ext_count += 1;
        witness
    }

    /// Throws an error.
    pub fn error(&mut self) {
        self.operations.push(DslIr::Error());
    }

    /// Materializes a usize into a variable.
    pub fn materialize(&mut self, num: Usize<C::N>) -> Var<C::N> {
        match num {
            Usize::Const(num) => self.eval(C::N::from_canonical_usize(num)),
            Usize::Var(num) => num,
        }
    }

    /// Store a felt in the public values buffer.
    pub fn write_public_value(&mut self, val: Felt<C::F>) {
        if self.nb_public_values.is_none() {
            self.nb_public_values = Some(self.eval(C::N::zero()));
            self.public_values_buffer = Some(self.dyn_array::<Felt<_>>(PV_BUFFER_MAX_SIZE));
        }

        let nb_public_values = self.nb_public_values.unwrap();
        let mut public_values_buffer = self.public_values_buffer.clone().unwrap();

        self.set(&mut public_values_buffer, nb_public_values, val);
        self.assign(&nb_public_values, nb_public_values + C::N::one());

        self.nb_public_values = Some(nb_public_values);
        self.public_values_buffer = Some(public_values_buffer);
    }

    /// Stores an array of felts in the public values buffer.
    pub fn write_public_values(&mut self, vals: &Array<C, Felt<C::F>>) {
        if self.nb_public_values.is_none() {
            self.nb_public_values = Some(self.eval(C::N::zero()));
            self.public_values_buffer = Some(self.dyn_array::<Felt<_>>(PV_BUFFER_MAX_SIZE));
        }

        let len = vals.len();

        let nb_public_values = self.nb_public_values.unwrap();
        let mut public_values_buffer = self.public_values_buffer.clone().unwrap();

        self.range(0, len).for_each(|i, builder| {
            let val = builder.get(vals, i);
            builder.set(&mut public_values_buffer, nb_public_values, val);
            builder.assign(&nb_public_values, nb_public_values + C::N::one());
        });

        self.nb_public_values = Some(nb_public_values);
        self.public_values_buffer = Some(public_values_buffer);
    }

    /// Hashes the public values buffer and calls the Commit command on the digest.
    pub fn commit_public_values(&mut self) {
        if self.nb_public_values.is_none() {
            self.nb_public_values = Some(self.eval(C::N::zero()));
            self.public_values_buffer = Some(self.dyn_array::<Felt<_>>(PV_BUFFER_MAX_SIZE));
        }

        let pv_buffer = self.public_values_buffer.clone().unwrap();
        pv_buffer.truncate(self, self.nb_public_values.unwrap().into());

        let pv_hash = self.poseidon2_hash(&pv_buffer);
        self.operations.push(DslIr::Commit(pv_hash.clone()));
    }

    pub fn commit_vkey_hash_circuit(&mut self, var: Var<C::N>) {
        self.operations.push(DslIr::CircuitCommitVkeyHash(var));
    }

    pub fn commit_commited_values_digest_circuit(&mut self, var: Var<C::N>) {
        self.operations
            .push(DslIr::CircuitCommitCommitedValuesDigest(var));
    }

    pub fn cycle_tracker(&mut self, name: &str) {
        self.operations.push(DslIr::CycleTracker(name.to_string()));
    }
}

/// A builder for the DSL that handles if statements.
pub struct IfBuilder<'a, C: Config> {
    lhs: SymbolicVar<C::N>,
    rhs: SymbolicVar<C::N>,
    is_eq: bool,
    pub(crate) builder: &'a mut Builder<C>,
}

/// A set of conditions that if statements can be based on.
enum IfCondition<N> {
    EqConst(N, N),
    NeConst(N, N),
    Eq(Var<N>, Var<N>),
    EqI(Var<N>, N),
    Ne(Var<N>, Var<N>),
    NeI(Var<N>, N),
}

impl<'a, C: Config> IfBuilder<'a, C> {
    pub fn then(mut self, mut f: impl FnMut(&mut Builder<C>)) {
        // Get the condition reduced from the expressions for lhs and rhs.
        let condition = self.condition();

        // Execute the `then` block and collect the instructions.
        let mut f_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );
        f(&mut f_builder);
        let then_instructions = f_builder.operations;

        // Dispatch instructions to the correct conditional block.
        match condition {
            IfCondition::EqConst(lhs, rhs) => {
                if lhs == rhs {
                    self.builder.operations.extend(then_instructions);
                }
            }
            IfCondition::NeConst(lhs, rhs) => {
                if lhs != rhs {
                    self.builder.operations.extend(then_instructions);
                }
            }
            IfCondition::Eq(lhs, rhs) => {
                let op = DslIr::IfEq(lhs, rhs, then_instructions, Default::default());
                self.builder.operations.push(op);
            }
            IfCondition::EqI(lhs, rhs) => {
                let op = DslIr::IfEqI(lhs, rhs, then_instructions, Default::default());
                self.builder.operations.push(op);
            }
            IfCondition::Ne(lhs, rhs) => {
                let op = DslIr::IfNe(lhs, rhs, then_instructions, Default::default());
                self.builder.operations.push(op);
            }
            IfCondition::NeI(lhs, rhs) => {
                let op = DslIr::IfNeI(lhs, rhs, then_instructions, Default::default());
                self.builder.operations.push(op);
            }
        }
    }

    pub fn then_or_else(
        mut self,
        mut then_f: impl FnMut(&mut Builder<C>),
        mut else_f: impl FnMut(&mut Builder<C>),
    ) {
        // Get the condition reduced from the expressions for lhs and rhs.
        let condition = self.condition();
        let mut then_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );

        // Execute the `then` and `else_then` blocks and collect the instructions.
        then_f(&mut then_builder);
        let then_instructions = then_builder.operations;

        let mut else_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );
        else_f(&mut else_builder);
        let else_instructions = else_builder.operations;

        // Dispatch instructions to the correct conditional block.
        match condition {
            IfCondition::EqConst(lhs, rhs) => {
                if lhs == rhs {
                    self.builder.operations.extend(then_instructions);
                } else {
                    self.builder.operations.extend(else_instructions);
                }
            }
            IfCondition::NeConst(lhs, rhs) => {
                if lhs != rhs {
                    self.builder.operations.extend(then_instructions);
                } else {
                    self.builder.operations.extend(else_instructions);
                }
            }
            IfCondition::Eq(lhs, rhs) => {
                let op = DslIr::IfEq(lhs, rhs, then_instructions, else_instructions);
                self.builder.operations.push(op);
            }
            IfCondition::EqI(lhs, rhs) => {
                let op = DslIr::IfEqI(lhs, rhs, then_instructions, else_instructions);
                self.builder.operations.push(op);
            }
            IfCondition::Ne(lhs, rhs) => {
                let op = DslIr::IfNe(lhs, rhs, then_instructions, else_instructions);
                self.builder.operations.push(op);
            }
            IfCondition::NeI(lhs, rhs) => {
                let op = DslIr::IfNeI(lhs, rhs, then_instructions, else_instructions);
                self.builder.operations.push(op);
            }
        }
    }

    fn condition(&mut self) -> IfCondition<C::N> {
        match (self.lhs.clone(), self.rhs.clone(), self.is_eq) {
            (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs), true) => {
                IfCondition::EqConst(lhs, rhs)
            }
            (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs), false) => {
                IfCondition::NeConst(lhs, rhs)
            }
            (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs), true) => IfCondition::EqI(rhs, lhs),
            (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs), false) => IfCondition::NeI(rhs, lhs),
            (SymbolicVar::Const(lhs), rhs, true) => {
                let rhs: Var<C::N> = self.builder.eval(rhs);
                IfCondition::EqI(rhs, lhs)
            }
            (SymbolicVar::Const(lhs), rhs, false) => {
                let rhs: Var<C::N> = self.builder.eval(rhs);
                IfCondition::NeI(rhs, lhs)
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs), true) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                IfCondition::EqI(lhs, rhs)
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs), false) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                IfCondition::NeI(lhs, rhs)
            }
            (lhs, SymbolicVar::Const(rhs), true) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                IfCondition::EqI(lhs, rhs)
            }
            (lhs, SymbolicVar::Const(rhs), false) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                IfCondition::NeI(lhs, rhs)
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs), true) => IfCondition::Eq(lhs, rhs),
            (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs), false) => IfCondition::Ne(lhs, rhs),
            (SymbolicVar::Val(lhs), rhs, true) => {
                let rhs: Var<C::N> = self.builder.eval(rhs);
                IfCondition::Eq(lhs, rhs)
            }
            (SymbolicVar::Val(lhs), rhs, false) => {
                let rhs: Var<C::N> = self.builder.eval(rhs);
                IfCondition::Ne(lhs, rhs)
            }
            (lhs, SymbolicVar::Val(rhs), true) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                IfCondition::Eq(lhs, rhs)
            }
            (lhs, SymbolicVar::Val(rhs), false) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                IfCondition::Ne(lhs, rhs)
            }
            (lhs, rhs, true) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                let rhs: Var<C::N> = self.builder.eval(rhs);
                IfCondition::Eq(lhs, rhs)
            }
            (lhs, rhs, false) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                let rhs: Var<C::N> = self.builder.eval(rhs);
                IfCondition::Ne(lhs, rhs)
            }
        }
    }
}

/// A builder for the DSL that handles for loops.
pub struct RangeBuilder<'a, C: Config> {
    start: Usize<C::N>,
    end: Usize<C::N>,
    step_size: usize,
    builder: &'a mut Builder<C>,
}

impl<'a, C: Config> RangeBuilder<'a, C> {
    pub fn step_by(mut self, step_size: usize) -> Self {
        self.step_size = step_size;
        self
    }

    pub fn for_each(self, mut f: impl FnMut(Var<C::N>, &mut Builder<C>)) {
        let step_size = C::N::from_canonical_usize(self.step_size);
        let loop_variable: Var<C::N> = self.builder.uninit();
        let mut loop_body_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );

        f(loop_variable, &mut loop_body_builder);

        let loop_instructions = loop_body_builder.operations;

        let op = DslIr::For(
            self.start,
            self.end,
            step_size,
            loop_variable,
            loop_instructions,
        );
        self.builder.operations.push(op);
    }
}
