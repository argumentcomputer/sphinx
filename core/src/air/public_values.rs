use core::fmt::Debug;
use core::mem::size_of;
use std::array;
use std::iter::once;

use itertools::Itertools;
use p3_field::{AbstractField, PrimeField32};
use serde::{Deserialize, Serialize};

use super::Word;
use crate::stark::PROOF_MAX_NUM_PVS;

/// The number of non padded elements in the SP1 proofs public values vec.
pub const SP1_PROOF_NUM_PV_ELTS: usize = size_of::<PublicValues<Word<u8>, u8>>();

/// The number of 32 bit words in the SP1 proof's committed value digest.
pub const PV_DIGEST_NUM_WORDS: usize = 8;

pub const POSEIDON_NUM_WORDS: usize = 8;

/// The PublicValues struct is used to store all of a shard proof's public values.
#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct PublicValues<W, T> {
    /// The hash of all the bytes that the guest program has written to public values.
    pub committed_value_digest: [W; PV_DIGEST_NUM_WORDS],

    /// The hash of all deferred proofs that have been witnessed in the VM. It will be rebuilt in
    /// recursive verification as the proofs get verified. The hash itself is a rolling poseidon2
    /// hash of each proof+vkey hash and the previous hash which is initially zero.
    pub deferred_proofs_digest: [W; POSEIDON_NUM_WORDS],

    /// The shard number.
    pub shard: T,

    /// The shard's start program counter.
    pub start_pc: T,

    /// The expected start program counter for the next shard.
    pub next_pc: T,

    /// The exit code of the program.  Only valid if halt has been executed.
    pub exit_code: T,
}

impl PublicValues<u32, u32> {
    /// Convert the public values into a vector of field elements.  This function will pad the vector
    /// to the maximum number of public values.
    pub fn to_vec<F: AbstractField>(&self) -> Vec<F> {
        let mut ret = self
            .committed_value_digest
            .iter()
            .flat_map(|w| Word::<F>::from(*w).into_iter())
            .chain(
                self.deferred_proofs_digest
                    .iter()
                    .flat_map(|w| Word::<F>::from(*w).into_iter()),
            )
            .chain(once(F::from_canonical_u32(self.shard)))
            .chain(once(F::from_canonical_u32(self.start_pc)))
            .chain(once(F::from_canonical_u32(self.next_pc)))
            .chain(once(F::from_canonical_u32(self.exit_code)))
            .collect_vec();

        assert!(
            ret.len() <= PROOF_MAX_NUM_PVS,
            "Too many public values: {}",
            ret.len()
        );

        ret.resize(PROOF_MAX_NUM_PVS, F::zero());

        ret
    }
}

impl<T: Clone> PublicValues<Word<T>, T> {
    /// Convert a vector of field elements into a PublicValues struct.
    pub fn from_vec(data: &[T]) -> Self {
        data.iter().cloned().collect::<Self>()
    }
}

impl<T, IT> FromIterator<IT> for PublicValues<Word<T>, T>
where
    IT: Into<T>,
{
    /// Construct a PublicValues struct by reading the first elements from an iterator
    fn from_iter<I: IntoIterator<Item = IT>>(iter: I) -> Self {
        let mut iter = iter.into_iter().map(IT::into);

        let committed_value_digest = array::from_fn(|_| (&mut iter).collect());
        let deferred_proofs_digest = array::from_fn(|_| (&mut iter).collect());
        // Collecting the remaining items into a tuple.  Note that it is only getting the first
        // four items, as the rest would be padded values.
        let shard = iter.next().unwrap();
        let start_pc = iter.next().unwrap();
        let next_pc = iter.next().unwrap();
        let exit_code = iter.next().unwrap();

        Self {
            committed_value_digest,
            deferred_proofs_digest,
            shard,
            start_pc,
            next_pc,
            exit_code,
        }
    }
}

impl<F: PrimeField32> PublicValues<Word<F>, F> {
    /// Returns the commit digest as a vector of little-endian bytes.
    pub fn commit_digest_bytes(&self) -> Vec<u8> {
        self.committed_value_digest
            .iter()
            .flat_map(|w| w.into_iter().map(|f| f.as_canonical_u32() as u8))
            .collect_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::air::public_values;

    /// Check that the PI_DIGEST_NUM_WORDS number match the zkVM crate's.
    #[test]
    fn test_public_values_digest_num_words_consistency_zkvm() {
        assert_eq!(
            public_values::PV_DIGEST_NUM_WORDS,
            wp1_zkvm::syscalls::PV_DIGEST_NUM_WORDS
        );
    }
}
