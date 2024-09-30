/// Utility function for converting u64s into u32 pairs.
pub fn u64_to_le_u32s(n: u64) -> [u32; 2] {
    let n = n.to_le_bytes();
    [
        u32::from_le_bytes(n[..4].try_into().unwrap()),
        u32::from_le_bytes(n[4..].try_into().unwrap()),
    ]
}

/// Utility function for converting a u32 LE pair into a u64.
pub fn u32_pair_to_u64(lo_word: u32, hi_word: u32) -> u64 {
    u64::from_le_bytes(
        lo_word
            .to_le_bytes()
            .into_iter()
            .chain(hi_word.to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    )
}
