pub mod array_serde;
mod buffer;
mod config;
pub mod ec;
mod logger;
mod options;
#[cfg(any(test, feature = "programs"))]
mod programs;
mod prove;
mod tracer;

use std::borrow::Borrow;

pub use buffer::*;
pub use config::*;
use hybrid_array::{Array, ArraySize};
pub use logger::*;
pub use options::*;
#[cfg(test)]
pub use programs::tests;
pub use prove::*;
pub use tracer::*;

use crate::{
    memory::MemoryCols,
    operations::field::params::{LimbWidth, Limbs},
};

pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

pub fn pad_to_power_of_two<const N: usize, T: Clone + Default>(values: &mut Vec<T>) {
    debug_assert!(values.len() % N == 0);
    let mut n_real_rows = values.len() / N;
    if n_real_rows < 8 {
        n_real_rows = 8;
    }
    values.resize(n_real_rows.next_power_of_two() * N, T::default());
}

pub fn pad_to_power_of_two_nongeneric<T: Clone + Default>(n: usize, values: &mut Vec<T>) {
    debug_assert!(values.len() % n == 0);
    let mut n_real_rows = values.len() / n;
    if n_real_rows == 0 || n_real_rows == 1 {
        n_real_rows = 8;
    }
    values.resize(n_real_rows.next_power_of_two() * n, T::default());
}

pub fn limbs_from_prev_access<T: Copy, M: MemoryCols<T>, U: LimbWidth>(cols: &[M]) -> Limbs<T, U> {
    cols.iter()
        .flat_map(|access| access.prev_value().0)
        .collect()
}

pub fn limbs_from_access<T: Copy, M: MemoryCols<T>, U: LimbWidth>(cols: &[M]) -> Limbs<T, U> {
    cols.iter().flat_map(|access| access.value().0).collect()
}

/// Pads `rows` to a length that is a power of two, using `row_fn` to generate new rows.
//
pub fn pad_rows<T: Clone>(rows: &mut Vec<T>, row_fn: impl Fn() -> T) {
    let nb_rows = rows.len();
    let mut padded_nb_rows = nb_rows.next_power_of_two();
    if padded_nb_rows < 8 {
        padded_nb_rows = 8;
    }
    if padded_nb_rows == nb_rows {
        return;
    }
    let dummy_row = row_fn();
    rows.resize(padded_nb_rows, dummy_row);
}

pub fn pad_rows_fixed<R: Clone>(
    rows: &mut Vec<R>,
    row_fn: impl Fn() -> R,
    size_log2: Option<usize>,
) {
    let nb_rows = rows.len();
    let dummy_row = row_fn();
    if let Some(size_log2) = size_log2 {
        let padded_nb_rows = 1 << size_log2;
        if nb_rows * 2 < padded_nb_rows {
            tracing::warn!(
                "fixed log2 rows can be potentially reduced: got {}, expected {}",
                nb_rows,
                padded_nb_rows
            );
        }
        assert!(
            nb_rows <= padded_nb_rows,
            "fixed log2 rows is too small: got {}, expected {}",
            nb_rows,
            padded_nb_rows
        );
        rows.resize(padded_nb_rows, dummy_row);
    } else {
        let mut padded_nb_rows = nb_rows.next_power_of_two();
        if padded_nb_rows < 8 {
            padded_nb_rows = 8;
        }
        if padded_nb_rows == nb_rows {
            return;
        }
        rows.resize(padded_nb_rows, dummy_row);
    }
}

/// Converts a slice of words to a byte array in little endian.
pub fn words_to_bytes_le<B: ArraySize>(words: &[u32]) -> <B as ArraySize>::ArrayType<u8> {
    debug_assert_eq!(words.len() * 4, B::USIZE);
    Array::try_from(
        &words
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect::<Vec<_>>()[..],
    )
    .unwrap()
    .into()
}

/// Converts a slice of words to a byte vector in little endian.
pub fn words_to_bytes_le_vec(words: &[u32]) -> Vec<u8> {
    words
        .iter()
        .flat_map(|word| word.to_le_bytes().to_vec())
        .collect::<Vec<_>>()
}

/// Converts a slice of words to a byte vector in big endian.
pub fn words_to_bytes_be_vec(words: &[u32]) -> Vec<u8> {
    words
        .iter()
        .flat_map(|word| word.to_be_bytes().to_vec())
        .collect::<Vec<_>>()
}

/// Converts a byte array in little endian to an array of words.
pub fn bytes_to_words_le<W: ArraySize>(bytes: &[u8]) -> <W as ArraySize>::ArrayType<u32> {
    debug_assert_eq!(bytes.len(), W::USIZE * 4);
    Array::try_from(
        &bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>()[..],
    )
    .unwrap()
    .into()
}

/// Converts a byte array in big endian to a slice of words.
pub fn bytes_to_words_be_vec(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
}

/// Converts a byte array in little endian to a vector of words.
pub fn bytes_to_words_le_vec(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
}

/// Converts a num to a string with commas every 3 digits.
pub fn num_to_comma_separated<T: ToString, B: Borrow<T>>(value: B) -> String {
    value
        .borrow()
        .to_string()
        .chars()
        .rev()
        .collect::<Vec<_>>()
        .chunks(3)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(",")
        .chars()
        .rev()
        .collect()
}

pub fn chunk_vec<T>(mut vec: Vec<T>, chunk_size: usize) -> Vec<Vec<T>> {
    let mut result = Vec::new();
    while !vec.is_empty() {
        let current_chunk_size = std::cmp::min(chunk_size, vec.len());
        let current_chunk = vec.drain(..current_chunk_size).collect::<Vec<T>>();
        result.push(current_chunk);
    }
    result
}

#[inline]
pub fn log2_strict_usize(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert_eq!(n.wrapping_shr(res), 1, "Not a power of two: {n}");
    res as usize
}
