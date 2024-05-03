use std::borrow::BorrowMut;

use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;

use super::{
    columns::{ShaCompressCols, NUM_SHA_COMPRESS_COLS},
    ShaCompressChip, SHA_COMPRESS_K,
};
use crate::{
    air::{MachineAir, Word},
    bytes::event::ByteRecord,
    runtime::{ExecutionRecord, Program},
    utils::pad_rows,
};

impl<F: PrimeField32> MachineAir<F> for ShaCompressChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "ShaCompress".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();
        for i in 0..input.sha_compress_events.len() {
            let mut event = input.sha_compress_events[i].clone();
            let shard = event.shard;

            let og_h = event.h;

            let mut octet_num_idx = 0;

            // Load a, b, c, d, e, f, g, h.
            for j in 0..8usize {
                let mut row = [F::zero(); NUM_SHA_COMPRESS_COLS];
                let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

                cols.shard = F::from_canonical_u32(event.shard);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.w_ptr = F::from_canonical_u32(event.w_ptr);
                cols.h_ptr = F::from_canonical_u32(event.h_ptr);

                cols.octet[j] = F::one();
                cols.octet_num[octet_num_idx] = F::one();

                cols.mem
                    .populate_read(event.h_read_records[j], &mut new_byte_lookup_events);
                cols.mem_addr = F::from_canonical_u32(event.h_ptr + (j * 4) as u32);

                cols.a = Word::from(event.h_read_records[0].value);
                cols.b = Word::from(event.h_read_records[1].value);
                cols.c = Word::from(event.h_read_records[2].value);
                cols.d = Word::from(event.h_read_records[3].value);
                cols.e = Word::from(event.h_read_records[4].value);
                cols.f = Word::from(event.h_read_records[5].value);
                cols.g = Word::from(event.h_read_records[6].value);
                cols.h = Word::from(event.h_read_records[7].value);

                cols.is_real = F::one();
                cols.start = cols.is_real * cols.octet_num[0] * cols.octet[0];
                rows.push(row);
            }

            // Performs the compress operation.
            for j in 0..64 {
                if j % 8 == 0 {
                    octet_num_idx += 1;
                }
                let mut row = [F::zero(); NUM_SHA_COMPRESS_COLS];
                let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

                cols.k = Word::from(SHA_COMPRESS_K[j]);
                cols.is_compression = F::one();
                cols.octet[j % 8] = F::one();
                cols.octet_num[octet_num_idx] = F::one();

                cols.shard = F::from_canonical_u32(event.shard);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.w_ptr = F::from_canonical_u32(event.w_ptr);
                cols.h_ptr = F::from_canonical_u32(event.h_ptr);
                cols.mem
                    .populate_read(event.w_i_read_records[j], &mut new_byte_lookup_events);
                cols.mem_addr = F::from_canonical_u32(event.w_ptr + (j * 4) as u32);

                let a = event.h[0];
                let b = event.h[1];
                let c = event.h[2];
                let d = event.h[3];
                let e = event.h[4];
                let f = event.h[5];
                let g = event.h[6];
                let h = event.h[7];
                cols.a = Word::from(a);
                cols.b = Word::from(b);
                cols.c = Word::from(c);
                cols.d = Word::from(d);
                cols.e = Word::from(e);
                cols.f = Word::from(f);
                cols.g = Word::from(g);
                cols.h = Word::from(h);

                let e_rr_6 = cols.e_rr_6.populate(output, shard, e, 6);
                let e_rr_11 = cols.e_rr_11.populate(output, shard, e, 11);
                let e_rr_25 = cols.e_rr_25.populate(output, shard, e, 25);
                let s1_intermediate = cols
                    .s1_intermediate
                    .populate(output, shard, e_rr_6, e_rr_11);
                let s1 = cols.s1.populate(output, shard, s1_intermediate, e_rr_25);

                let e_and_f = cols.e_and_f.populate(output, shard, e, f);
                let e_not = cols.e_not.populate(output, shard, e);
                let e_not_and_g = cols.e_not_and_g.populate(output, shard, e_not, g);
                let ch = cols.ch.populate(output, shard, e_and_f, e_not_and_g);

                let temp1 =
                    cols.temp1
                        .populate(output, shard, h, s1, ch, event.w[j], SHA_COMPRESS_K[j]);

                let a_rr_2 = cols.a_rr_2.populate(output, shard, a, 2);
                let a_rr_13 = cols.a_rr_13.populate(output, shard, a, 13);
                let a_rr_22 = cols.a_rr_22.populate(output, shard, a, 22);
                let s0_intermediate = cols
                    .s0_intermediate
                    .populate(output, shard, a_rr_2, a_rr_13);
                let s0 = cols.s0.populate(output, shard, s0_intermediate, a_rr_22);

                let a_and_b = cols.a_and_b.populate(output, shard, a, b);
                let a_and_c = cols.a_and_c.populate(output, shard, a, c);
                let b_and_c = cols.b_and_c.populate(output, shard, b, c);
                let maj_intermediate = cols
                    .maj_intermediate
                    .populate(output, shard, a_and_b, a_and_c);
                let maj = cols.maj.populate(output, shard, maj_intermediate, b_and_c);

                let temp2 = cols.temp2.populate(output, shard, s0, maj);

                let d_add_temp1 = cols.d_add_temp1.populate(output, shard, d, temp1);
                let temp1_add_temp2 = cols.temp1_add_temp2.populate(output, shard, temp1, temp2);

                event.h[7] = g;
                event.h[6] = f;
                event.h[5] = e;
                event.h[4] = d_add_temp1;
                event.h[3] = c;
                event.h[2] = b;
                event.h[1] = a;
                event.h[0] = temp1_add_temp2;

                cols.is_real = F::one();
                cols.start = cols.is_real * cols.octet_num[0] * cols.octet[0];

                rows.push(row);
            }

            let mut v: [u32; 8] = [0, 1, 2, 3, 4, 5, 6, 7].map(|i| event.h[i]);

            octet_num_idx += 1;
            // Store a, b, c, d, e, f, g, h.
            for j in 0..8usize {
                let mut row = [F::zero(); NUM_SHA_COMPRESS_COLS];
                let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

                cols.shard = F::from_canonical_u32(event.shard);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.w_ptr = F::from_canonical_u32(event.w_ptr);
                cols.h_ptr = F::from_canonical_u32(event.h_ptr);

                cols.octet[j] = F::one();
                cols.octet_num[octet_num_idx] = F::one();

                cols.finalize_add
                    .populate(output, shard, og_h[j], event.h[j]);
                cols.mem
                    .populate_write(event.h_write_records[j], &mut new_byte_lookup_events);
                cols.mem_addr = F::from_canonical_u32(event.h_ptr + (j * 4) as u32);

                v[j] = event.h[j];
                cols.a = Word::from(v[0]);
                cols.b = Word::from(v[1]);
                cols.c = Word::from(v[2]);
                cols.d = Word::from(v[3]);
                cols.e = Word::from(v[4]);
                cols.f = Word::from(v[5]);
                cols.g = Word::from(v[6]);
                cols.h = Word::from(v[7]);

                match j {
                    0 => cols.finalized_operand = cols.a,
                    1 => cols.finalized_operand = cols.b,
                    2 => cols.finalized_operand = cols.c,
                    3 => cols.finalized_operand = cols.d,
                    4 => cols.finalized_operand = cols.e,
                    5 => cols.finalized_operand = cols.f,
                    6 => cols.finalized_operand = cols.g,
                    7 => cols.finalized_operand = cols.h,
                    _ => panic!("unsupported j"),
                };

                cols.is_real = F::one();
                cols.is_last_row = cols.octet[7] * cols.octet_num[9];
                cols.start = cols.is_real * cols.octet_num[0] * cols.octet[0];

                rows.push(row);
            }
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || [F::zero(); NUM_SHA_COMPRESS_COLS]);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA_COMPRESS_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.sha_compress_events.is_empty()
    }
}
