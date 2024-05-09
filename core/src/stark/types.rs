use std::{
    collections::HashMap,
    fmt::Debug,
    fs::File,
    io::{BufReader, BufWriter, Seek},
};

use bincode::{deserialize_from, Error};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::VerticalPair,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use size::Size;
use tracing::trace;

use crate::air::SP1_PROOF_NUM_PV_ELTS;

use super::{Challenge, Com, OpeningProof, PcsProverData, StarkGenericConfig, Val};

pub type QuotientOpenedValues<T> = Vec<T>;

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "PcsProverData<SC>: Serialize"))]
#[serde(bound(deserialize = "PcsProverData<SC>: Deserialize<'de>"))]
pub struct ShardMainData<SC: StarkGenericConfig> {
    pub traces: Vec<RowMajorMatrix<Val<SC>>>,
    pub main_commit: Com<SC>,
    pub main_data: PcsProverData<SC>,
    pub chip_ordering: HashMap<String, usize>,
    pub index: usize,
    pub public_values: Vec<SC::Val>,
}

impl<SC: StarkGenericConfig> ShardMainData<SC> {
    pub fn new(
        traces: Vec<RowMajorMatrix<Val<SC>>>,
        main_commit: Com<SC>,
        main_data: PcsProverData<SC>,
        chip_ordering: HashMap<String, usize>,
        index: usize,
        public_values: Vec<Val<SC>>,
    ) -> Self {
        Self {
            traces,
            main_commit,
            main_data,
            chip_ordering,
            index,
            public_values,
        }
    }

    pub fn save(&self, file: File) -> Result<ShardMainDataWrapper<SC>, Error>
    where
        ShardMainData<SC>: Serialize,
    {
        let mut writer = BufWriter::new(&file);
        bincode::serialize_into(&mut writer, self)?;
        drop(writer);
        let metadata = file.metadata()?;
        let bytes_written = metadata.len();
        trace!(
            "wrote {} while saving ShardMainData",
            Size::from_bytes(bytes_written)
        );
        Ok(ShardMainDataWrapper::TempFile(file, bytes_written))
    }

    pub fn to_in_memory(self) -> ShardMainDataWrapper<SC> {
        ShardMainDataWrapper::InMemory(self)
    }
}

pub enum ShardMainDataWrapper<SC: StarkGenericConfig> {
    InMemory(ShardMainData<SC>),
    TempFile(File, u64),
    Empty(),
}

impl<SC: StarkGenericConfig> ShardMainDataWrapper<SC> {
    pub fn materialize(self) -> Result<ShardMainData<SC>, Error>
    where
        ShardMainData<SC>: DeserializeOwned,
    {
        match self {
            Self::InMemory(data) => Ok(data),
            Self::TempFile(file, _) => {
                let mut buffer = BufReader::new(&file);
                buffer.seek(std::io::SeekFrom::Start(0))?;
                let data = deserialize_from(&mut buffer)?;
                Ok(data)
            }
            Self::Empty() => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardCommitment<C> {
    pub main_commit: C,
    pub permutation_commit: C,
    pub quotient_commit: C,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirOpenedValues<T> {
    pub local: Vec<T>,
    pub next: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipOpenedValues<T> {
    pub preprocessed: AirOpenedValues<T>,
    pub main: AirOpenedValues<T>,
    pub permutation: AirOpenedValues<T>,
    pub quotient: Vec<Vec<T>>,
    pub cumulative_sum: T,
    pub log_degree: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardOpenedValues<T> {
    pub chips: Vec<ChipOpenedValues<T>>,
}

/// The maximum number of elements that can be stored in the public values vec.  Both SP1 and recursive
/// proofs need to pad their public_values vec to this length.  This is required since the recursion
/// verification program expects the public values vec to be fixed length.
pub const PROOF_MAX_NUM_PVS: usize = SP1_PROOF_NUM_PV_ELTS;

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct ShardProof<SC: StarkGenericConfig> {
    pub index: usize,
    pub commitment: ShardCommitment<Com<SC>>,
    pub opened_values: ShardOpenedValues<Challenge<SC>>,
    pub opening_proof: OpeningProof<SC>,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<Val<SC>>,
}

impl<T: Send + Sync + Clone> AirOpenedValues<T> {
    pub fn view(&self) -> VerticalPair<RowMajorMatrixView<'_, T>, RowMajorMatrixView<'_, T>> {
        let a = RowMajorMatrixView::new_row(&self.local);
        let b = RowMajorMatrixView::new_row(&self.next);
        VerticalPair::new(a, b)
    }
}

impl<SC: StarkGenericConfig> ShardProof<SC> {
    pub fn cumulative_sum(&self) -> Challenge<SC> {
        self.opened_values
            .chips
            .iter()
            .map(|c| c.cumulative_sum)
            .sum()
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct MachineProof<SC: StarkGenericConfig> {
    pub shard_proofs: Vec<ShardProof<SC>>,
}

impl<SC: StarkGenericConfig> Debug for MachineProof<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof")
            .field("shard_proofs", &self.shard_proofs.len())
            .finish()
    }
}

/// PublicValuesDigest is a hash of all the public values that a zkvm program has committed to.
pub struct PublicValuesDigest(pub [u8; 32]);

impl From<[u32; 8]> for PublicValuesDigest {
    fn from(arr: [u32; 8]) -> Self {
        let mut bytes = [0u8; 32];
        for (i, word) in arr.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        PublicValuesDigest(bytes)
    }
}

/// DeferredDigest is a hash of all the deferred proofs that have been witnessed in the VM.
pub struct DeferredDigest(pub [u8; 32]);

impl From<[u32; 8]> for DeferredDigest {
    fn from(arr: [u32; 8]) -> Self {
        let mut bytes = [0u8; 32];
        for (i, word) in arr.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        DeferredDigest(bytes)
    }
}
