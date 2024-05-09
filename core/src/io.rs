use crate::utils::Buffer;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Standard input for the prover.
#[derive(Serialize, Deserialize, Clone)]
pub struct SP1Stdin {
    /// Input stored as a vec of vec of bytes. It's stored this way because the read syscall reads
    /// a vec of bytes at a time.
    pub buffer: Vec<Vec<u8>>,
    pub ptr: usize,
}

/// Public values for the prover.
#[derive(Serialize, Deserialize)]
pub struct SP1PublicValues {
    // TODO: fix
    pub buffer: Buffer,
}

impl Default for SP1Stdin {
    fn default() -> Self {
        Self::new()
    }
}

impl SP1Stdin {
    /// Create a new `SP1Stdin`.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            ptr: 0,
        }
    }

    /// Create a `SP1Stdin` from a slice of bytes.
    pub fn from(data: &[u8]) -> Self {
        Self {
            buffer: vec![data.to_vec()],
            ptr: 0,
        }
    }

    /// Read a value from the buffer.
    pub fn read<T: Serialize + DeserializeOwned>(&mut self) -> T {
        let result: T =
            bincode::deserialize(&self.buffer[self.ptr]).expect("failed to deserialize");
        self.ptr += 1;
        result
    }

    /// Read a slice of bytes from the buffer.
    pub fn read_slice(&mut self, slice: &mut [u8]) {
        slice.copy_from_slice(&self.buffer[self.ptr]);
        self.ptr += 1;
    }

    /// Write a value to the buffer.
    pub fn write<T: Serialize>(&mut self, data: &T) {
        let mut tmp = Vec::new();
        bincode::serialize_into(&mut tmp, data).expect("serialization failed");
        self.buffer.push(tmp);
    }

    /// Write a slice of bytes to the buffer.
    pub fn write_slice(&mut self, slice: &[u8]) {
        self.buffer.push(slice.to_vec());
    }

    pub fn write_vec(&mut self, vec: Vec<u8>) {
        self.buffer.push(vec);
    }
}

impl Default for SP1PublicValues {
    fn default() -> Self {
        Self::new()
    }
}

impl SP1PublicValues {
    /// Create a new `SP1PublicValues`.
    pub fn new() -> Self {
        Self {
            buffer: Buffer::new(),
        }
    }

    /// Create a `SP1PublicValues` from a slice of bytes.
    pub fn from(data: &[u8]) -> Self {
        Self {
            buffer: Buffer::from(data),
        }
    }

    /// Read a value from the buffer.    
    pub fn read<T: Serialize + DeserializeOwned>(&mut self) -> T {
        self.buffer.read()
    }

    /// Read a slice of bytes from the buffer.
    pub fn read_slice(&mut self, slice: &mut [u8]) {
        self.buffer.read_slice(slice);
    }

    /// Write a value to the buffer.
    pub fn write<T: Serialize + DeserializeOwned>(&mut self, data: &T) {
        self.buffer.write(data);
    }

    /// Write a slice of bytes to the buffer.
    pub fn write_slice(&mut self, slice: &[u8]) {
        self.buffer.write_slice(slice);
    }
}

impl AsRef<[u8]> for SP1PublicValues {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.data
    }
}

pub mod proof_serde {
    use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};

    use crate::stark::{MachineProof, StarkGenericConfig};

    pub fn serialize<S, SC: StarkGenericConfig + Serialize>(
        proof: &MachineProof<SC>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let bytes = bincode::serialize(proof).unwrap();
            let hex_bytes = hex::encode(bytes);
            serializer.serialize_str(&hex_bytes)
        } else {
            proof.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D, SC: StarkGenericConfig + DeserializeOwned>(
        deserializer: D,
    ) -> Result<MachineProof<SC>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let hex_bytes = String::deserialize(deserializer).unwrap();
            let bytes = hex::decode(hex_bytes).unwrap();
            let proof = bincode::deserialize(&bytes).map_err(serde::de::Error::custom)?;
            Ok(proof)
        } else {
            MachineProof::<SC>::deserialize(deserializer)
        }
    }
}
