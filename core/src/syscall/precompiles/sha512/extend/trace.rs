use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use std::borrow::BorrowMut;

use super::{Sha512ExtendChip, Sha512ExtendCols, Sha512ExtendEvent, NUM_SHA512_EXTEND_COLS};
use crate::{
    air::{EventLens, MachineAir, WithEvents},
    bytes::{event::ByteRecord, ByteLookupEvent, ByteOpcode},
    runtime::{ExecutionRecord, Program},
};

impl<'a> WithEvents<'a> for Sha512ExtendChip {
    type Events = &'a [Sha512ExtendEvent];
}

impl<F: PrimeField32> MachineAir<F> for Sha512ExtendChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Sha512Extend".to_string()
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
            let mut row = [F::zero(); NUM_SHA512_EXTEND_COLS];
            let cols: &mut Sha512ExtendCols<F> = row.as_mut_slice().borrow_mut();
            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u32(event.channel);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.w_ptr = F::from_canonical_u32(event.w_ptr);
            cols.i = F::from_canonical_u32(event.i);
            // 15 < i < 80
            new_byte_lookup_events.push(ByteLookupEvent {
                opcode: ByteOpcode::LTU,
                shard,
                channel: event.channel,
                a1: 1,
                a2: 0,
                b: 15,
                c: event.i,
            });
            new_byte_lookup_events.push(ByteLookupEvent {
                opcode: ByteOpcode::LTU,
                shard,
                channel: event.channel,
                a1: 1,
                a2: 0,
                b: event.i,
                c: 80,
            });

            cols.w_i_minus_15[0].populate(
                event.channel,
                event.w_i_minus_15_reads[0],
                &mut new_byte_lookup_events,
            );
            cols.w_i_minus_15[1].populate(
                event.channel,
                event.w_i_minus_15_reads[1],
                &mut new_byte_lookup_events,
            );
            cols.w_i_minus_2[0].populate(
                event.channel,
                event.w_i_minus_2_reads[0],
                &mut new_byte_lookup_events,
            );
            cols.w_i_minus_2[1].populate(
                event.channel,
                event.w_i_minus_2_reads[1],
                &mut new_byte_lookup_events,
            );
            cols.w_i_minus_16[0].populate(
                event.channel,
                event.w_i_minus_16_reads[0],
                &mut new_byte_lookup_events,
            );
            cols.w_i_minus_16[1].populate(
                event.channel,
                event.w_i_minus_16_reads[1],
                &mut new_byte_lookup_events,
            );
            cols.w_i_minus_7[0].populate(
                event.channel,
                event.w_i_minus_7_reads[0],
                &mut new_byte_lookup_events,
            );
            cols.w_i_minus_7[1].populate(
                event.channel,
                event.w_i_minus_7_reads[1],
                &mut new_byte_lookup_events,
            );

            // FIXME
            fn u32_vec_to_u64(val: Vec<u32>) -> u64 {
                u64::from_le_bytes(
                    val.into_iter()
                        .flat_map(|x| x.to_le_bytes())
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap(),
                )
            }

            // `s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)`
            let w_i_minus_15_lo = event.w_i_minus_15_reads[0].value;
            let w_i_minus_15_hi = event.w_i_minus_15_reads[1].value;
            let w_i_minus_15 = u32_vec_to_u64(vec![w_i_minus_15_lo, w_i_minus_15_hi]);

            let w_i_minus_15_rr_1 =
                cols.w_i_minus_15_rr_1
                    .populate(output, shard, event.channel, w_i_minus_15, 1);
            let w_i_minus_15_rr_8 =
                cols.w_i_minus_15_rr_8
                    .populate(output, shard, event.channel, w_i_minus_15, 8);
            let w_i_minus_15_rs_7 =
                cols.w_i_minus_15_rs_7
                    .populate(output, shard, event.channel, w_i_minus_15, 7);

            let s0_intermediate = cols.s0_intermediate.populate(
                output,
                shard,
                event.channel,
                w_i_minus_15_rr_1,
                w_i_minus_15_rr_8,
            );
            let s0 = cols.s0.populate(
                output,
                shard,
                event.channel,
                s0_intermediate,
                w_i_minus_15_rs_7,
            );

            // `s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)`
            let w_i_minus_2_lo = event.w_i_minus_2_reads[0].value;
            let w_i_minus_2_hi = event.w_i_minus_2_reads[1].value;
            let w_i_minus_2 = u32_vec_to_u64(vec![w_i_minus_2_lo, w_i_minus_2_hi]);

            let w_i_minus_2_rr_19 =
                cols.w_i_minus_2_rr_19
                    .populate(output, shard, event.channel, w_i_minus_2, 19);
            let w_i_minus_2_rr_61 =
                cols.w_i_minus_2_rr_61
                    .populate(output, shard, event.channel, w_i_minus_2, 61);
            let w_i_minus_2_rs_6 =
                cols.w_i_minus_2_rs_6
                    .populate(output, shard, event.channel, w_i_minus_2, 6);

            let s1_intermediate = cols.s1_intermediate.populate(
                output,
                shard,
                event.channel,
                w_i_minus_2_rr_19,
                w_i_minus_2_rr_61,
            );
            let s1 = cols.s1.populate(
                output,
                shard,
                event.channel,
                s1_intermediate,
                w_i_minus_2_rs_6,
            );

            // Compute `s2`.
            let w_i_minus_7_lo = event.w_i_minus_7_reads[0].value;
            let w_i_minus_7_hi = event.w_i_minus_7_reads[1].value;
            let w_i_minus_7 = u32_vec_to_u64(vec![w_i_minus_7_lo, w_i_minus_7_hi]);

            let w_i_minus_16_lo = event.w_i_minus_16_reads[0].value;
            let w_i_minus_16_hi = event.w_i_minus_16_reads[1].value;
            let w_i_minus_16 = u32_vec_to_u64(vec![w_i_minus_16_lo, w_i_minus_16_hi]);

            // `s2 := w[i-16] + s0 + w[i-7] + s1`.
            let s2_0 = cols.s2[0].populate(output, shard, event.channel, w_i_minus_16, s0);
            let s2_1 = cols.s2[1].populate(output, shard, event.channel, s2_0, w_i_minus_7);
            let s2_2 = cols.s2[2].populate(output, shard, event.channel, s2_1, s1);
            let w_i = u32_vec_to_u64(vec![event.w_i_writes[0].value, event.w_i_writes[1].value]);
            assert_eq!(s2_2, w_i);

            cols.w_i[0].populate(
                event.channel,
                event.w_i_writes[0],
                &mut new_byte_lookup_events,
            );
            cols.w_i[1].populate(
                event.channel,
                event.w_i_writes[1],
                &mut new_byte_lookup_events,
            );

            rows.push(row);
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        let nb_rows = rows.len();
        let mut padded_nb_rows = nb_rows.next_power_of_two();
        if padded_nb_rows == 2 || padded_nb_rows == 1 {
            padded_nb_rows = 4;
        }
        for _ in nb_rows..padded_nb_rows {
            let row = [F::zero(); NUM_SHA512_EXTEND_COLS];
            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA512_EXTEND_COLS,
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut Sha512ExtendCols<F> = trace.values
                [i * NUM_SHA512_EXTEND_COLS..(i + 1) * NUM_SHA512_EXTEND_COLS]
                .borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.sha512_extend_events.is_empty()
    }
}
