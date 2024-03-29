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

#[cfg(test)]
mod tests {
    use hybrid_array::{sizes::U4, Array, ArraySize};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct Foo<U: ArraySize>(
        #[serde(with = "crate::utils::array_serde::ArraySerde")] Array<u32, U>,
    );

    #[test]
    fn test_roundtrip_array() {
        // create an array, serialize with bincode, deserialize, and compare
        let mut arr = Array::<u32, U4>::default();
        arr[0] = 1;
        arr[1] = 2;
        arr[2] = 3;
        arr[3] = 4;
        let foo = Foo::<U4>(arr);
        let serialized = bincode::serialize(&foo).unwrap();
        let deserialized: Foo<U4> = bincode::deserialize(&serialized).unwrap();
        assert_eq!(foo, deserialized);
    }
}
