use super::BYTE_SIZE;
use crate::air::WORD_SIZE;

pub(crate) fn get_msb(a: [u8; WORD_SIZE]) -> u8 {
    (a[WORD_SIZE - 1] >> (BYTE_SIZE - 1)) & 1
}
