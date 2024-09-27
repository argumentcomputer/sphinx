use std::borrow::BorrowMut;

use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use super::{
    columns::{Sha512CompressCols, NUM_SHA512_COMPRESS_COLS},
    Sha512CompressChip, Sha512CompressEvent,
};
use crate::{
    air::{EventLens, MachineAir, WithEvents},
    bytes::{event::ByteRecord, ByteLookupEvent, ByteOpcode},
    runtime::{ExecutionRecord, Program},
    utils::pad_rows,
};

impl<'a> WithEvents<'a> for Sha512CompressChip {
    type Events = &'a [Sha512CompressEvent];
}

// FIXME
fn u64_to_u32x2(n: u64) -> [u32; 2] {
    let n = n.to_le_bytes();
    [
        u32::from_le_bytes(n[..4].try_into().unwrap()),
        u32::from_le_bytes(n[4..].try_into().unwrap()),
    ]
}

impl<F: PrimeField32> MachineAir<F> for Sha512CompressChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Sha512Compress".to_string()
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();
        for evt_idx in 0..input.events().len() {
            let event = input.events()[evt_idx].clone();
            let shard = event.shard;
            let channel = event.channel;

            let mut row = [F::zero(); NUM_SHA512_COMPRESS_COLS];
            let cols: &mut Sha512CompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u32(event.channel);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.w_ptr = F::from_canonical_u32(event.w_ptr);
            cols.h_ptr = F::from_canonical_u32(event.h_ptr);
            cols.i = F::from_canonical_u32(event.i);
            cols.is_real = F::one();

            // i < 80
            new_byte_lookup_events.push(ByteLookupEvent {
                opcode: ByteOpcode::LTU,
                shard,
                channel: event.channel,
                a1: 1,
                a2: 0,
                b: event.i,
                c: 80,
            });

            cols.k_i[0].populate(
                event.channel,
                event.k_i_read_records[0],
                &mut new_byte_lookup_events,
            );
            cols.k_i[1].populate(
                event.channel,
                event.k_i_read_records[1],
                &mut new_byte_lookup_events,
            );

            cols.w_i[0].populate(
                event.channel,
                event.w_i_read_records[0],
                &mut new_byte_lookup_events,
            );
            cols.w_i[1].populate(
                event.channel,
                event.w_i_read_records[1],
                &mut new_byte_lookup_events,
            );

            cols.i_mem.populate(
                event.channel,
                event.i_write_record,
                &mut new_byte_lookup_events,
            );

            // Performs the compress operation.
            let a = event.h[0];
            let b = event.h[1];
            let c = event.h[2];
            let d = event.h[3];
            let e = event.h[4];
            let f = event.h[5];
            let g = event.h[6];
            let h = event.h[7];

            let e_rr_14 = cols.e_rr_14.populate(output, shard, channel, e, 14);
            let e_rr_18 = cols.e_rr_18.populate(output, shard, channel, e, 18);
            let e_rr_41 = cols.e_rr_41.populate(output, shard, channel, e, 41);
            let s1_intermediate = cols
                .s1_intermediate
                .populate(output, shard, channel, e_rr_14, e_rr_18);
            let s1 = cols
                .s1
                .populate(output, shard, channel, s1_intermediate, e_rr_41);

            let e_and_f = cols.e_and_f.populate(output, shard, channel, e, f);
            let e_not = cols.e_not.populate(output, shard, channel, e);
            let e_not_and_g = cols.e_not_and_g.populate(output, shard, channel, e_not, g);
            let ch = cols
                .ch
                .populate(output, shard, channel, e_and_f, e_not_and_g);

            let temp1_0 = cols.temp1[0].populate(output, shard, channel, h, s1);
            let temp1_1 = cols.temp1[1].populate(output, shard, channel, temp1_0, ch);
            let temp1_2 = cols.temp1[2].populate(output, shard, channel, temp1_1, event.k_i);
            let temp1 = cols.temp1[3].populate(output, shard, channel, temp1_2, event.w_i);

            let a_rr_28 = cols.a_rr_28.populate(output, shard, channel, a, 28);
            let a_rr_34 = cols.a_rr_34.populate(output, shard, channel, a, 34);
            let a_rr_39 = cols.a_rr_39.populate(output, shard, channel, a, 39);
            let s0_intermediate = cols
                .s0_intermediate
                .populate(output, shard, channel, a_rr_28, a_rr_34);
            let s0 = cols
                .s0
                .populate(output, shard, channel, s0_intermediate, a_rr_39);

            let a_and_b = cols.a_and_b.populate(output, shard, channel, a, b);
            let a_and_c = cols.a_and_c.populate(output, shard, channel, a, c);
            let b_and_c = cols.b_and_c.populate(output, shard, channel, b, c);
            let maj_intermediate = cols
                .maj_intermediate
                .populate(output, shard, channel, a_and_b, a_and_c);
            let maj = cols
                .maj
                .populate(output, shard, channel, maj_intermediate, b_and_c);

            let temp2 = cols.temp2.populate(output, shard, channel, s0, maj);

            let d_add_temp1 = cols.d_add_temp1.populate(output, shard, channel, d, temp1);
            let temp1_add_temp2 = cols
                .temp1_add_temp2
                .populate(output, shard, channel, temp1, temp2);

            let out_h = [temp1_add_temp2, a, b, c, d_add_temp1, e, f, g];

            // Populate the output memory writes, and assert that the values written match.
            for j in 0..8 {
                cols.h[2 * j].populate(
                    event.channel,
                    event.h_write_records[2 * j],
                    &mut new_byte_lookup_events,
                );
                cols.h[2 * j + 1].populate(
                    event.channel,
                    event.h_write_records[2 * j + 1],
                    &mut new_byte_lookup_events,
                );
                let out = u64_to_u32x2(out_h[j]);
                assert_eq!(event.h_write_records[2 * j].value, out[0]);
                assert_eq!(event.h_write_records[2 * j + 1].value, out[1]);
            }

            rows.push(row);
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || [F::zero(); NUM_SHA512_COMPRESS_COLS]);

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA512_COMPRESS_COLS,
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut Sha512CompressCols<F> = trace.values
                [i * NUM_SHA512_COMPRESS_COLS..(i + 1) * NUM_SHA512_COMPRESS_COLS]
                .borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.sha512_compress_events.is_empty()
    }
}
