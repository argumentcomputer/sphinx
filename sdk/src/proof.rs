use std::{fmt::Debug, fs::File, path::Path};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use strum_macros::{EnumDiscriminants, EnumTryAs};

use sphinx_core::stark::{MachineVerificationError, ShardProof};
use sphinx_prover::{CoreSC, InnerSC, PlonkBn254Proof, SphinxPublicValues, SphinxStdin};

/// A proof generated with SP1 of a particular proof mode.
#[derive(Debug, Clone, Serialize, Deserialize, EnumDiscriminants, EnumTryAs)]
#[strum_discriminants(derive(Default, Hash, PartialOrd, Ord))]
#[strum_discriminants(name(SphinxProofKind))]
pub enum SphinxProof {
    #[strum_discriminants(default)]
    Core(Vec<ShardProof<CoreSC>>),
    Compressed(ShardProof<InnerSC>),
    Plonk(PlonkBn254Proof),
}

/// A proof generated with SP1, bundled together with stdin, public values, and the SP1 version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphinxProofWithPublicValues {
    pub proof: SphinxProof,
    pub stdin: SphinxStdin,
    pub public_values: SphinxPublicValues,
    pub sphinx_version: String,
}

impl SphinxProofWithPublicValues {
    /// Saves the proof to a path.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        bincode::serialize_into(File::create(path).expect("failed to open file"), self)
            .map_err(Into::into)
    }

    /// Loads a proof from a path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        bincode::deserialize_from(File::open(path).expect("failed to open file"))
            .map_err(Into::into)
    }
}

pub type SphinxCoreProofVerificationError = MachineVerificationError<CoreSC>;

pub type SphinxCompressedProofVerificationError = MachineVerificationError<InnerSC>;
