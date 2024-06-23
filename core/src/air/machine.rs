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
    /// the input events that this AIR needs to get a reference to in order to lay out its trace
    type InputEvents: 'a;

    // the output events that this AIR produces
    type OutputEvents: 'a;
}

/// A trait intended for implementation on Records that may store events related to Chips,
/// The purpose of this trait is to provide a way to access the events relative to a specific
/// Chip, as specified by its `WithEvents` trait implementation.
///
/// The name is inspired by (but not conformant to) functional optics ( https://doi.org/10.1145/1232420.1232424 )
pub trait EventLens<T: for<'b> WithEvents<'b>>: Indexed {
    fn events(&self) -> <T as WithEvents<'_>>::InputEvents;
}

pub trait EventMutLens<T: for<'b> WithEvents<'b>> {
    fn add_events(&mut self, events: <T as WithEvents<'_>>::OutputEvents);
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

impl<'a, T, R, U, F> EventLens<U> for Proj<'a, T, R, F>
where
    T: for<'b> WithEvents<'b>,
    R: EventLens<T>,
    U: for<'b> WithEvents<'b>,
    // see https://github.com/rust-lang/rust/issues/86702 for the empty parameter
    F: for<'c> Fn(<T as WithEvents<'c>>::InputEvents, &'c ()) -> <U as WithEvents<'c>>::InputEvents,
{
    fn events<'c>(&'c self) -> <U as WithEvents<'c>>::InputEvents {
        let events: <T as WithEvents<'c>>::InputEvents = self.record.events();
        (self.projection)(events, &())
    }
}

impl<'a, T, R, F> Indexed for Proj<'a, T, R, F>
where
    T: for<'b> WithEvents<'b>,
    R: EventLens<T> + Indexed,
{
    fn index(&self) -> u32 {
        self.record.index()
    }
}

/// if I have an EventMutLens from T::Events, and a way (F) to deduce T::Events from U::Events,
/// I can compose them to get an EventMutLens from U::Events.
pub struct Inj<'a, T, R, F>
where
    T: for<'b> WithEvents<'b>,
    R: EventMutLens<T>,
{
    record: &'a mut R,
    injection: F,
    _phantom: PhantomData<T>,
}

/// A constructor for the projection from T::Events to U::Events.
impl<'a, T, R, F> Inj<'a, T, R, F>
where
    T: for<'b> WithEvents<'b>,
    R: EventMutLens<T>,
{
    pub fn new(record: &'a mut R, injection: F) -> Self {
        Self {
            record,
            injection,
            _phantom: PhantomData,
        }
    }
}

impl<'a, T, R, U, F> EventMutLens<U> for Inj<'a, T, R, F>
where
    T: for<'b> WithEvents<'b>,
    R: EventMutLens<T>,
    U: for<'b> WithEvents<'b>,
    // see https://github.com/rust-lang/rust/issues/86702 for the empty parameter
    F: for<'c> Fn(
        <U as WithEvents<'c>>::OutputEvents,
        &'c (),
    ) -> <T as WithEvents<'c>>::OutputEvents,
{
    fn add_events(&mut self, events: <U as WithEvents<'_>>::OutputEvents) {
        let events: <T as WithEvents<'_>>::OutputEvents = (self.injection)(events, &());
        self.record.add_events(events);
    }
}
//////////////// end of shenanigans destined for the derive macros. ////////////////

/// An AIR that is part of a multi table AIR arithmetization.
pub trait MachineAir<F: Field>: BaseAir<F> + for<'a> WithEvents<'a> {
    /// The execution record containing events for producing the air trace.
    type Record: MachineRecord + EventLens<Self> + EventMutLens<Self>;

    type Program: MachineProgram<F>;

    /// A unique identifier for this AIR as part of a machine.
    fn name(&self) -> String;

    /// Generate the trace for a given execution record.
    ///
    /// - `input` is the execution record containing the events to be written to the trace.
    /// - `output` is the execution record containing events that the `MachineAir` can add to
    ///    the record such as byte lookup requests.
    fn generate_trace<EL: EventLens<Self>, OL: EventMutLens<Self>>(
        &self,
        input: &EL,
        output: &mut OL,
    ) -> RowMajorMatrix<F>;

    /// Generate the dependencies for a given execution record.
    fn generate_dependencies<EL: EventLens<Self>, OL: EventMutLens<Self>>(
        &self,
        input: &EL,
        output: &mut OL,
    ) {
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
