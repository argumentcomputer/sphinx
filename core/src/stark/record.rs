use hashbrown::HashMap;

use p3_field::AbstractField;

use crate::air::{PublicValues, Word};

pub trait PublicValued {
    fn public_values<F: AbstractField + Clone>(&self) -> PublicValues<Word<F>, F>;
}

pub trait MachineRecord: Default + Sized + Send + Sync + Clone {
    type Config;

    fn stats(&self) -> HashMap<String, usize>;

    fn append(&mut self, other: &mut Self);

    fn register_nonces(&mut self, _opts: &Self::Config) {}

    fn public_values<F: AbstractField>(&self) -> Vec<F>;
}
