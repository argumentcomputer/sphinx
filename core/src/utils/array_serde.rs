use std::fmt;
use std::marker::PhantomData;
use std::mem::MaybeUninit;

use hybrid_array::{Array, ArraySize};
use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeTuple, Serializer};

pub(crate) struct PartiallyInitialized<T, U: ArraySize>(
    pub(crate) Option<MaybeUninit<Array<T, U>>>,
    pub(crate) usize,
);

impl<T, U: ArraySize> PartiallyInitialized<T, U> {
    #[inline]
    pub(crate) fn new() -> Self {
        PartiallyInitialized(Some(MaybeUninit::uninit()), 0)
    }
}

impl<T, U: ArraySize> Drop for PartiallyInitialized<T, U> {
    fn drop(&mut self) {
        if !core::mem::needs_drop::<T>() {
            return;
        }
        if let Some(arr) = &mut self.0 {
            while self.1 > 0 {
                self.1 -= 1;
                let offs = self.1;
                let p = (arr.as_mut_ptr() as *mut T).wrapping_add(offs);
                unsafe {
                    core::ptr::drop_in_place::<T>(p);
                }
            }
        }
    }
}

pub struct ArraySerde;

impl ArraySerde {
    pub fn serialize<T: Serialize, U: ArraySize, S>(
        value: &Array<T, U>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(value.len())?;
        for elem in &value[..] {
            seq.serialize_element(elem)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, T: Clone + Deserialize<'de>, U: ArraySize>(
        deserializer: D,
    ) -> Result<Array<T, U>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor<T> {
            element: PhantomData<T>,
        }

        impl<'de, T, U: ArraySize> Visitor<'de> for ArrayVisitor<Array<T, U>>
        where
            T: Deserialize<'de>,
        {
            type Value = Array<T, U>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array of length {}", U::USIZE)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Array<T, U>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                unsafe {
                    let mut arr = PartiallyInitialized::<T, U>::new();
                    {
                        let p = arr.0.as_mut().unwrap();
                        for i in 0..U::USIZE {
                            let p = (p.as_mut_ptr() as *mut T).wrapping_add(i);
                            let val = seq
                                .next_element()?
                                .ok_or_else(|| Error::invalid_length(i, &self))?;
                            core::ptr::write(p, val);
                            arr.1 += 1;
                        }
                    }
                    let initialized = arr.0.take().unwrap().assume_init();
                    Ok(initialized)
                }
            }
        }

        let visitor = ArrayVisitor {
            element: PhantomData,
        };
        deserializer.deserialize_tuple(U::USIZE, visitor)
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
