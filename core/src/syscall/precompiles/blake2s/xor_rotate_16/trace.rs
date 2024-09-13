use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use std::borrow::BorrowMut;

use super::{
    Blake2sXorRotate16Chip, Blake2sXorRotate16Cols, Blake2sXorRotate16Event,
    NUM_BLAKE2S_XOR_ROTATE_16_COLS,
};
use crate::{
    air::{EventLens, MachineAir, WithEvents},
    bytes::event::ByteRecord,
    runtime::{ExecutionRecord, Program},
};

impl<'a> WithEvents<'a> for Blake2sXorRotate16Chip {
    type Events = &'a [Blake2sXorRotate16Event];
}

impl<F: PrimeField32> MachineAir<F> for Blake2sXorRotate16Chip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Blake2sXorRotate16".to_string()
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();
        for i in 0..input.events().len() {
            let event = input.events()[i].clone();
            let shard = event.shard;
            for j in 0..48usize {
                let mut row = [F::zero(); NUM_BLAKE2S_XOR_ROTATE_16_COLS];
                let cols: &mut Blake2sXorRotate16Cols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::one();
                cols.populate_flags(j);
                cols.shard = F::from_canonical_u32(event.shard);
                cols.channel = F::from_canonical_u32(event.channel);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.w_ptr = F::from_canonical_u32(event.w_ptr);

                cols.w_0.populate(
                    event.channel,
                    event.w_0_reads[j],
                    &mut new_byte_lookup_events,
                );
                cols.w_1.populate(
                    event.channel,
                    event.w_1_reads[j],
                    &mut new_byte_lookup_events,
                );
                cols.w_2.populate(
                    event.channel,
                    event.w_2_reads[j],
                    &mut new_byte_lookup_events,
                );
                cols.w_3.populate(
                    event.channel,
                    event.w_3_reads[j],
                    &mut new_byte_lookup_events,
                );
                cols.w_4.populate(
                    event.channel,
                    event.w_4_reads[j],
                    &mut new_byte_lookup_events,
                );
                cols.w_5.populate(
                    event.channel,
                    event.w_5_reads[j],
                    &mut new_byte_lookup_events,
                );
                cols.w_6.populate(
                    event.channel,
                    event.w_6_reads[j],
                    &mut new_byte_lookup_events,
                );
                cols.w_7.populate(
                    event.channel,
                    event.w_7_reads[j],
                    &mut new_byte_lookup_events,
                );

                let w_0 = event.w_0_reads[j].value;
                let w_1 = event.w_1_reads[j].value;
                let w_2 = event.w_2_reads[j].value;
                let w_3 = event.w_3_reads[j].value;
                let w_4 = event.w_4_reads[j].value;
                let w_5 = event.w_5_reads[j].value;
                let w_6 = event.w_6_reads[j].value;
                let w_7 = event.w_7_reads[j].value;

                let xor_0 = cols.xor_0.populate(output, shard, event.channel, w_0, w_4);

                cols.rot_0.populate(output, shard, event.channel, xor_0, 16);

                let xor_1 = cols.xor_1.populate(output, shard, event.channel, w_1, w_5);

                cols.rot_1.populate(output, shard, event.channel, xor_1, 16);

                let xor_2 = cols.xor_2.populate(output, shard, event.channel, w_2, w_6);

                cols.rot_2.populate(output, shard, event.channel, xor_2, 16);

                let xor_3 = cols.xor_3.populate(output, shard, event.channel, w_3, w_7);

                cols.rot_3.populate(output, shard, event.channel, xor_3, 16);

                cols.w_16.populate(
                    event.channel,
                    event.w_16_writes[j],
                    &mut new_byte_lookup_events,
                );

                cols.w_17.populate(
                    event.channel,
                    event.w_17_writes[j],
                    &mut new_byte_lookup_events,
                );

                cols.w_18.populate(
                    event.channel,
                    event.w_18_writes[j],
                    &mut new_byte_lookup_events,
                );

                cols.w_19.populate(
                    event.channel,
                    event.w_19_writes[j],
                    &mut new_byte_lookup_events,
                );

                rows.push(row);
            }
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        let nb_rows = rows.len();
        let mut padded_nb_rows = nb_rows.next_power_of_two();
        if padded_nb_rows == 2 || padded_nb_rows == 1 {
            padded_nb_rows = 4;
        }
        for i in nb_rows..padded_nb_rows {
            let mut row = [F::zero(); NUM_BLAKE2S_XOR_ROTATE_16_COLS];
            let cols: &mut Blake2sXorRotate16Cols<F> = row.as_mut_slice().borrow_mut();
            cols.populate_flags(i);
            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BLAKE2S_XOR_ROTATE_16_COLS,
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut Blake2sXorRotate16Cols<F> = trace.values
                [i * NUM_BLAKE2S_XOR_ROTATE_16_COLS..(i + 1) * NUM_BLAKE2S_XOR_ROTATE_16_COLS]
                .borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.blake2s_xor_rotate_16_events.is_empty()
    }
}
