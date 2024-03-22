use hybrid_array::{Array, ArraySize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// TODO(FG): improve this with serde_with::TryFomIntoRef
pub struct ArraySerde;

impl ArraySerde {
    pub fn serialize<T: Serialize, U: ArraySize, S>(
        value: &Array<T, U>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.serialize(serializer)
    }

    pub fn deserialize<'de, D, T: Clone + Deserialize<'de>, U: ArraySize>(
        deserializer: D,
    ) -> Result<Array<T, U>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // TODO: remove the double copy
        let v = Vec::<T>::deserialize(deserializer)?;
        Array::<T, U>::try_from(&v[..]).map_err(serde::de::Error::custom)
    }
}
