use std::borrow::Borrow;
use std::{fs::File, path::Path};

use anyhow::Result;
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
use p3_field::PrimeField;
use p3_field::{AbstractField, PrimeField32, TwoAdicField};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sphinx_core::{
    io::{SphinxPublicValues, SphinxStdin},
    stark::{ShardProof, StarkGenericConfig, StarkProvingKey, StarkVerifyingKey},
    utils::DIGEST_SIZE,
};
use sphinx_primitives::poseidon2_hash;
use sphinx_recursion_core::{air::RecursionPublicValues, stark::config::BabyBearPoseidon2Outer};
use sphinx_recursion_gnark_ffi::plonk_bn254::PlonkBn254Proof;
use thiserror::Error;

use crate::utils::words_to_bytes_be;
use crate::{utils::babybear_bytes_to_bn254, words_to_bytes};
use crate::{utils::babybears_to_bn254, CoreSC, InnerSC};

/// The information necessary to generate a proof for a given RISC-V program.
#[derive(Clone, Serialize, Deserialize)]
pub struct SphinxProvingKey {
    pub pk: StarkProvingKey<CoreSC>,
    pub elf: Vec<u8>,
    /// Verifying key is also included as we need it for recursion
    pub vk: SphinxVerifyingKey,
}

/// The information necessary to verify a proof for a given RISC-V program.
#[derive(Clone, Serialize, Deserialize)]
pub struct SphinxVerifyingKey {
    pub vk: StarkVerifyingKey<CoreSC>,
}

/// A trait for keys that can be hashed into a digest.
pub trait HashableKey {
    /// Hash the key into a digest of BabyBear elements.
    fn hash_babybear(&self) -> [BabyBear; DIGEST_SIZE];

    /// Hash the key into a digest of  u32 elements.
    fn hash_u32(&self) -> [u32; DIGEST_SIZE];

    fn hash_bn254(&self) -> Bn254Fr {
        babybears_to_bn254(&self.hash_babybear())
    }

    fn bytes32(&self) -> String {
        let vkey_digest_bn254 = self.hash_bn254();
        format!(
            "0x{:0>64}",
            vkey_digest_bn254.as_canonical_biguint().to_str_radix(16)
        )
    }

    /// Hash the key into a digest of bytes elements.
    fn hash_bytes(&self) -> [u8; DIGEST_SIZE * 4] {
        words_to_bytes_be(&self.hash_u32())
    }
}

impl HashableKey for SphinxVerifyingKey {
    fn hash_babybear(&self) -> [BabyBear; DIGEST_SIZE] {
        self.vk.hash_babybear()
    }

    fn hash_u32(&self) -> [u32; DIGEST_SIZE] {
        self.vk.hash_u32()
    }
}

impl<SC: StarkGenericConfig<Val = BabyBear, Domain = TwoAdicMultiplicativeCoset<BabyBear>>>
    HashableKey for StarkVerifyingKey<SC>
where
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: AsRef<[BabyBear; DIGEST_SIZE]>,
{
    fn hash_babybear(&self) -> [BabyBear; DIGEST_SIZE] {
        let prep_domains = self.chip_information.iter().map(|(_, domain, _)| domain);
        let num_inputs = DIGEST_SIZE + 1 + (4 * prep_domains.len());
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.commit.as_ref());
        inputs.push(self.pc_start);
        for domain in prep_domains {
            inputs.push(BabyBear::from_canonical_usize(domain.log_n));
            let size = 1 << domain.log_n;
            inputs.push(BabyBear::from_canonical_usize(size));
            let g = BabyBear::two_adic_generator(domain.log_n);
            inputs.push(domain.shift);
            inputs.push(g);
        }

        poseidon2_hash(inputs)
    }

    fn hash_u32(&self) -> [u32; 8] {
        self.hash_babybear()
            .into_iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

/// A proof of a RISCV ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(serialize = "P: Serialize"))]
#[serde(bound(deserialize = "P: DeserializeOwned"))]
pub struct SphinxProofWithMetadata<P: Clone> {
    pub proof: P,
    pub stdin: SphinxStdin,
    pub public_values: SphinxPublicValues,
}

impl<P: Serialize + DeserializeOwned + Clone> SphinxProofWithMetadata<P> {
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        bincode::serialize_into(File::create(path).expect("failed to open file"), self)
            .map_err(Into::into)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        bincode::deserialize_from(File::open(path).expect("failed to open file"))
            .map_err(Into::into)
    }
}

impl<P: std::fmt::Debug + Clone> std::fmt::Debug for SphinxProofWithMetadata<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SP1ProofWithMetadata")
            .field("proof", &self.proof)
            .finish()
    }
}

/// A proof of an SP1 program without any wrapping.
pub type SphinxCoreProof = SphinxProofWithMetadata<SphinxCoreProofData>;

/// An SP1 proof that has been recursively reduced into a single proof. This proof can be verified
/// within SP1 programs.
pub type SphinxReducedProof = SphinxProofWithMetadata<SphinxReducedProofData>;

/// An SP1 proof that has been wrapped into a single PLONK proof and can be verified onchain.
pub type SphinxPlonkBn254Proof = SphinxProofWithMetadata<SphinxPlonkBn254ProofData>;

/// An SP1 proof that has been wrapped into a single PLONK proof and can be verified onchain.
pub type SphinxPlonkProof = SphinxProofWithMetadata<SphinxPlonkProofData>;

#[derive(Serialize, Deserialize, Clone)]
pub struct SphinxCoreProofData(pub Vec<ShardProof<CoreSC>>);
#[derive(Serialize, Deserialize, Clone)]
pub struct SphinxReducedProofData(pub ShardProof<InnerSC>);

#[derive(Serialize, Deserialize, Clone)]
pub struct SphinxPlonkBn254ProofData(pub PlonkBn254Proof);

#[derive(Serialize, Deserialize, Clone)]
pub struct SphinxPlonkProofData(pub PlonkBn254Proof);

/// An intermediate proof which proves the execution over a range of shards.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(serialize = "ShardProof<SC>: Serialize"))]
#[serde(bound(deserialize = "ShardProof<SC>: Deserialize<'de>"))]
pub struct SphinxReduceProof<SC: StarkGenericConfig> {
    pub proof: ShardProof<SC>,
}

impl SphinxReduceProof<BabyBearPoseidon2Outer> {
    pub fn sphinx_vkey_digest_babybear(&self) -> [BabyBear; 8] {
        let proof = &self.proof;
        let pv: &RecursionPublicValues<BabyBear> = proof.public_values.as_slice().borrow();
        pv.sphinx_vk_digest
    }

    pub fn sphinx_vkey_digest_bn254(&self) -> Bn254Fr {
        babybears_to_bn254(&self.sphinx_vkey_digest_babybear())
    }

    pub fn sphinx_commited_values_digest_bn254(&self) -> Bn254Fr {
        let proof = &self.proof;
        let pv: &RecursionPublicValues<BabyBear> = proof.public_values.as_slice().borrow();
        let committed_values_digest_bytes: [BabyBear; 32] =
            words_to_bytes(&pv.committed_value_digest)
                .try_into()
                .unwrap();
        babybear_bytes_to_bn254(&committed_values_digest_bytes)
    }
}

/// A proof that can be reduced along with other proofs into one proof.
#[derive(Serialize, Deserialize, Clone)]
pub enum SphinxReduceProofWrapper {
    Core(SphinxReduceProof<CoreSC>),
    Recursive(SphinxReduceProof<InnerSC>),
}

#[derive(Error, Debug)]
pub enum SphinxRecursionProverError {}
