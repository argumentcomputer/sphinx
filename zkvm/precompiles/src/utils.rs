use std::{
    ops::{Mul, Shl, Shr},
    slice,
};

use hybrid_array::{
    sizes::{U16, U4},
    typenum::B1,
    Array, ArraySize,
};

pub trait CurveOperations<N: ArraySize = U16> {
    const GENERATOR: N::ArrayType<u32>;
    fn add_assign(limbs: &mut N::ArrayType<u32>, other: &N::ArrayType<u32>);
    fn double(limbs: &mut N::ArrayType<u32>);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffinePoint<C: CurveOperations<N>, N: ArraySize = U16> {
    pub(crate) limbs: N::ArrayType<u32>,
    _marker: std::marker::PhantomData<C>,
}

impl<N: ArraySize, C: CurveOperations<N>> AffinePoint<C, N> {
    const GENERATOR: N::ArrayType<u32> = C::GENERATOR;

    pub const fn generator_in_affine() -> Self {
        Self {
            limbs: Self::GENERATOR,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn new(limbs: N::ArrayType<u32>) -> Self {
        Self {
            limbs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn from_array(limbs: Array<u32, N>) -> Self {
        Self {
            limbs: limbs.into(),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn double(&mut self) {
        C::double(&mut self.limbs);
    }

    pub fn add_assign(&mut self, other: &AffinePoint<C, N>) {
        C::add_assign(&mut self.limbs, &other.limbs);
    }
}

impl<N: ArraySize + Shl<B1, Output = O>, O: ArraySize, C: CurveOperations<N>> AffinePoint<C, N> {
    /// Construct an AffinePoint from the x and y coordinates. The coordinates are expected to be
    /// in little-endian byte order.
    pub fn from(x_bytes: &O::ArrayType<u8>, y_bytes: &O::ArrayType<u8>) -> Self {
        let mut limbs = Array::<u32, N>::default();

        // Safety : by the type logic
        let x = unsafe {
            slice::from_raw_parts(
                x_bytes.as_ref().as_ptr() as *const u32,
                x_bytes.as_ref().len() / 4,
            )
        };
        let y = unsafe {
            slice::from_raw_parts(
                y_bytes.as_ref().as_ptr() as *const u32,
                y_bytes.as_ref().len() / 4,
            )
        };

        // assumes N divisible by 2
        // TODO(FG): encode in the types?
        let n = limbs.len();
        limbs[..n / 2].copy_from_slice(x);
        limbs[n / 2..].copy_from_slice(y);
        Self::from_array(limbs)
    }
}

impl<N: ArraySize + Mul<U4, Output = O>, O: ArraySize, C: CurveOperations<N>> AffinePoint<C, N> {
    pub fn from_le_bytes(limbs: &O::ArrayType<u8>) -> Self {
        // Safety : by the type logic
        let v = unsafe {
            slice::from_raw_parts(
                limbs.as_ref().as_ptr() as *const u32,
                limbs.as_ref().len() / 4,
            )
        };
        Self::from_array(Array::try_from(v).unwrap())
    }

    pub fn to_le_bytes(&self) -> O::ArrayType<u8> {
        // Safety : by the type logic
        let v = unsafe {
            slice::from_raw_parts(
                self.limbs.as_ref().as_ptr() as *const u8,
                self.limbs.as_ref().len() * 4,
            )
        };
        Array::try_from(v).unwrap().into()
    }
}

impl<N: ArraySize + Shr<B1, Output = O>, O: ArraySize, C: CurveOperations<N> + Clone>
    AffinePoint<C, N>
where
    N::ArrayType<u32>: Clone,
{
    pub fn mul_assign(&mut self, scalar: &O::ArrayType<u32>) {
        let mut res: Option<Self> = None;
        let mut temp = self.clone();

        for &words in scalar.as_ref().iter() {
            for i in 0..32 {
                if (words >> i) & 1 == 1 {
                    match res.as_mut() {
                        Some(res) => res.add_assign(&temp.clone()),
                        None => res = Some(temp.clone()),
                    };
                }

                temp.double();
            }
        }

        *self = res.unwrap();
    }
}
