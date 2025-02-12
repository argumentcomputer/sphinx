use std::marker::PhantomData;

use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
pub use sphinx_derive::MachineAir;

use crate::{
    runtime::Program,
    stark::{Indexed, MachineRecord},
};

/// A description of the events related to this AIR.
pub trait WithEvents<'a>: Sized {
    /// output of a functional lens from the Record to
    /// refs of those events relative to the AIR.
    type Events: 'a;
}

/// A trait intended for implementation on Records that may store events related to Chips,
/// The purpose of this trait is to provide a way to access the events relative to a specific
/// Chip, as specified by its `WithEvents` trait implementation.
///
/// The name is inspired by (but not conformant to) functional optics ( https://doi.org/10.1145/1232420.1232424 )
pub trait EventLens<T: for<'b> WithEvents<'b>>: Indexed {
    fn events(&self) -> <T as WithEvents<'_>>::Events;
}

//////////////// Derive macro shenanigans ////////////////////////////////////////////////
// The following is *only* useful for the derive macros, you should *not* use this directly.
//
/// Hereafter, Lens composition explained pedantically: all this is saying is that
/// if I have an EventLens to T::Events, and a way (F) to deduce U::Events from that,
/// I can compose them to get an EventLens to U::Events.
pub struct Proj<'a, T, R, F>
where
    T: for<'b> WithEvents<'b>,
    R: EventLens<T>,
{
    record: &'a R,
    projection: F,
    _phantom: PhantomData<T>,
}

/// A constructor for the projection from T::Events to U::Events.
impl<'a, T, R, F> Proj<'a, T, R, F>
where
    T: for<'b> WithEvents<'b>,
    R: EventLens<T>,
{
    pub fn new(record: &'a R, projection: F) -> Self {
        Self {
            record,
            projection,
            _phantom: PhantomData,
        }
    }
}

impl<T, R, U, F> EventLens<U> for Proj<'_, T, R, F>
where
    T: for<'b> WithEvents<'b>,
    R: EventLens<T>,
    U: for<'b> WithEvents<'b>,
    // see https://github.com/rust-lang/rust/issues/86702 for the empty parameter
    F: for<'c> Fn(<T as WithEvents<'c>>::Events, &'c ()) -> <U as WithEvents<'c>>::Events,
{
    fn events<'c>(&'c self) -> <U as WithEvents<'c>>::Events {
        let events: <T as WithEvents<'c>>::Events = self.record.events();
        (self.projection)(events, &())
    }
}

impl<T, R, F> Indexed for Proj<'_, T, R, F>
where
    T: for<'b> WithEvents<'b>,
    R: EventLens<T> + Indexed,
{
    fn index(&self) -> u32 {
        self.record.index()
    }
}
//////////////// end of shenanigans destined for the derive macros. ////////////////

/// An AIR that is part of a multi table AIR arithmetization.
pub trait MachineAir<F: Field>: BaseAir<F> + for<'a> WithEvents<'a> {
    /// The execution record containing events for producing the air trace.
    type Record: MachineRecord + EventLens<Self>;

    type Program: MachineProgram<F>;

    /// A unique identifier for this AIR as part of a machine.
    fn name(&self) -> String;

    /// Generate the trace for a given execution record.
    ///
    /// - `input` is the execution record containing the events to be written to the trace.
    /// - `output` is the execution record containing events that the `MachineAir` can add to
    ///    the record such as byte lookup requests.
    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        output: &mut Self::Record,
    ) -> RowMajorMatrix<F>;

    /// Generate the dependencies for a given execution record.
    fn generate_dependencies<EL: EventLens<Self>>(&self, input: &EL, output: &mut Self::Record) {
        self.generate_trace(input, output);
    }

    /// Whether this execution record contains events for this air.
    fn included(&self, shard: &Self::Record) -> bool;

    /// The width of the preprocessed trace.
    fn preprocessed_width(&self) -> usize {
        0
    }

    /// Generate the preprocessed trace given a specific program.
    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        None
    }
}

pub trait MachineProgram<F>: Send + Sync {
    fn pc_start(&self) -> F;
}

impl<F: Field> MachineProgram<F> for Program {
    fn pc_start(&self) -> F {
        F::from_canonical_u32(self.pc_start)
    }
}
