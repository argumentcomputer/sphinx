use crate::lookup::InteractionKind;

/// An interaction is a cross-table lookup.
pub struct AirInteraction<E> {
    pub values: Vec<E>,
    pub multiplicity: E,
    pub kind: InteractionKind,
}

impl<E> AirInteraction<E> {
    /// Create a new interaction.
    pub fn new(
        value_iter: impl IntoIterator<Item = E>,
        multiplicity: E,
        kind: InteractionKind,
    ) -> Self {
        Self {
            values: value_iter.into_iter().collect(),
            multiplicity,
            kind,
        }
    }
}
