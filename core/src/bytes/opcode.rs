use p3_field::Field;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{bytes::NUM_BYTE_OPS, runtime::Opcode};

/// A byte opcode which the chip can process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ByteOpcode {
    /// Bitwise AND.
    AND = 0,

    /// Bitwise OR.
    OR = 1,

    /// Bitwise XOR.
    XOR = 2,

    /// Shift Left.
    SLL = 3,

    /// U8 Range check.
    U8Range = 4,

    /// Shift right with carry.
    ShrCarry = 5,

    /// Byte less than unsigned.
    LTU = 6,

    /// The most significant bit of the given byte.
    MSB = 7,

    /// U16 Range check.
    U16Range = 8,
}

impl ByteOpcode {
    const OPCODES: [Self; NUM_BYTE_OPS] = [
        ByteOpcode::AND,
        ByteOpcode::OR,
        ByteOpcode::XOR,
        ByteOpcode::SLL,
        ByteOpcode::U8Range,
        ByteOpcode::ShrCarry,
        ByteOpcode::LTU,
        ByteOpcode::MSB,
        ByteOpcode::U16Range,
    ];

    /// Get all the byte opcodes.
    pub fn all() -> Vec<Self> {
        Self::OPCODES.to_vec()
    }

    /// Convert the opcode to a field element.
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u8(self as u8)
    }
}

impl TryFrom<Opcode> for ByteOpcode {
    type Error = OpcodeConversionError;

    fn try_from(value: Opcode) -> Result<Self, Self::Error> {
        match value {
            Opcode::AND => Ok(Self::AND),
            Opcode::OR => Ok(Self::OR),
            Opcode::XOR => Ok(Self::XOR),
            Opcode::SLL => Ok(Self::SLL),
            _ => Err(OpcodeConversionError::InvalidOpcode(value)),
        }
    }
}

#[derive(Error, Debug)]
pub enum OpcodeConversionError {
    #[error("invalid opcode for ByteChip: {0:?}")]
    InvalidOpcode(Opcode),
}
