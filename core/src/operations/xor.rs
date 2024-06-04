use p3_field::Field;
use sphinx_derive::AlignedBorrow;

use crate::air::ByteAirBuilder;
use crate::air::Word;
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::bytes::ByteOpcode;
use crate::disassembler::WORD_SIZE;
use crate::runtime::ExecutionRecord;

/// A set of columns needed to compute the xor of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct XorOperation<T> {
    /// The result of `x ^ y`.
    pub value: Word<T>,
}

impl<F: Field> XorOperation<F> {
    pub fn populate(&mut self, record: &mut ExecutionRecord, shard: u32, x: u32, y: u32) -> u32 {
        let expected = x ^ y;
        let x_bytes = x.to_le_bytes();
        let y_bytes = y.to_le_bytes();
        for i in 0..WORD_SIZE {
            let xor = x_bytes[i] ^ y_bytes[i];
            self.value[i] = F::from_canonical_u8(xor);

            let byte_event = ByteLookupEvent {
                shard,
                opcode: ByteOpcode::XOR,
                a1: u32::from(xor),
                a2: 0,
                b: u32::from(x_bytes[i]),
                c: u32::from(y_bytes[i]),
            };
            record.add_byte_lookup_event(byte_event);
        }
        expected
    }

    pub fn eval<AB: ByteAirBuilder<F = F>>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: XorOperation<AB::Var>,
        shard: AB::Var,
        is_real: AB::Var,
    ) {
        for i in 0..WORD_SIZE {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
                cols.value[i],
                a[i],
                b[i],
                shard,
                is_real,
            );
        }
    }
}
