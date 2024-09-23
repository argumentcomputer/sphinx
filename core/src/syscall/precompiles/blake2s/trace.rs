use crate::bytes::event::ByteRecord;
use crate::syscall::precompiles::blake2s::Blake2sRoundCols;
use crate::syscall::precompiles::blake2s::{
    Blake2sRoundChip, Blake2sRoundEvent, R_1, R_2, R_3, R_4,
};
use crate::utils::pad_rows;
use crate::{
    air::{EventLens, MachineAir, WithEvents},
    runtime::{ExecutionRecord, Program},
};
use core::borrow::BorrowMut;
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

impl<'a> WithEvents<'a> for Blake2sRoundChip {
    type Events = &'a [Blake2sRoundEvent];
}

impl<F: PrimeField32> MachineAir<F> for Blake2sRoundChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Blake2sRoundChip".to_string()
    }

    fn generate_trace<EL: EventLens<Self>>(
        &self,
        input: &EL,
        output: &mut Self::Record,
    ) -> RowMajorMatrix<F> {
        let mut rows = vec![];
        let width = <Blake2sRoundChip as BaseAir<F>>::width(self);
        let mut new_byte_lookup_events = Vec::new();
        for event in input.events() {
            let shard = event.shard;
            let mut row = vec![F::zero(); width];
            let cols: &mut Blake2sRoundCols<F> = row.as_mut_slice().borrow_mut();

            cols.clk = F::from_canonical_u32(event.clk);
            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u32(event.channel);
            cols.a_ptr = F::from_canonical_u32(event.a_ptr);
            cols.b_ptr = F::from_canonical_u32(event.b_ptr);

            // populate all v, m
            for i in 0..16usize {
                cols.a[i].populate(
                    event.channel,
                    event.a_reads_writes[i],
                    &mut new_byte_lookup_events,
                );
                cols.b[i].populate(event.channel, event.b_reads[i], &mut new_byte_lookup_events);
            }

            // populate extra-zeroes
            // TODO: replace Add4 with Add3 operation and avoid this
            for i in 16..24usize {
                cols.b[i].populate(event.channel, event.b_reads[i], &mut new_byte_lookup_events);
            }

            let mut v0_outer = [0u32; 4];
            let mut v1_outer = [0u32; 4];
            let mut v2_outer = [0u32; 4];
            let mut v3_outer = [0u32; 4];

            // 1x (m0, R1, R2)
            for i in 0..4usize {
                let v0 = event.a_reads_writes[i].prev_value;
                let v1 = event.a_reads_writes[i + 4].prev_value;
                let v2 = event.a_reads_writes[i + 8].prev_value;
                let v3 = event.a_reads_writes[i + 12].prev_value;
                let m1 = event.b_reads[i].value;
                let zero1 = event.b_reads[i + 16].value;
                let zero2 = event.b_reads[i + 20].value;
                assert_eq!(zero1, 0);
                assert_eq!(zero2, 0);

                // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le());
                let v0_new = cols.add[i].populate(output, shard, event.channel, v0, v1, m1, zero1);

                // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
                let temp = cols.xor[i].populate(output, shard, event.channel, v3, v0_new);
                let v3_new =
                    cols.rotate_right[i].populate(output, shard, event.channel, temp, R_1 as usize);

                // v[2] = v[2].wrapping_add(v[3]);
                let v2_new = cols.add[i + 4].populate(
                    output,
                    shard,
                    event.channel,
                    v2,
                    v3_new,
                    zero1,
                    zero2,
                );

                // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
                let temp = cols.xor[i + 4].populate(output, shard, event.channel, v1, v2_new);
                let v1_new = cols.rotate_right[i + 4].populate(
                    output,
                    shard,
                    event.channel,
                    temp,
                    R_2 as usize,
                );

                v0_outer[i] = v0_new;
                v1_outer[i] = v1_new;
                v2_outer[i] = v2_new;
                v3_outer[i] = v3_new;
            }

            // 2x (m1, R3, R4)
            for i in 0..4usize {
                let v0 = v0_outer[i];
                let v1 = v1_outer[i];
                let v2 = v2_outer[i];
                let v3 = v3_outer[i];
                let m2 = event.b_reads[i + 4].value;
                let zero1 = event.b_reads[i + 16].value;
                let zero2 = event.b_reads[i + 20].value;

                // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le()); (m2)
                let v0_new =
                    cols.add[i + 8].populate(output, shard, event.channel, v0, v1, m2, zero1);

                // v[3] = (v[3] ^ v[0]).rotate_right_const(rd); (R3)
                let temp = cols.xor[i + 8].populate(output, shard, event.channel, v3, v0_new);
                let v3_new = cols.rotate_right[i + 8].populate(
                    output,
                    shard,
                    event.channel,
                    temp,
                    R_3 as usize,
                );

                // v[2] = v[2].wrapping_add(v[3]);
                let v2_new = cols.add[i + 4 + 8].populate(
                    output,
                    shard,
                    event.channel,
                    v2,
                    v3_new,
                    zero1,
                    zero2,
                );

                // v[1] = (v[1] ^ v[2]).rotate_right_const(rb); (R4)
                let temp = cols.xor[i + 4 + 8].populate(output, shard, event.channel, v1, v2_new);
                let v1_new = cols.rotate_right[i + 4 + 8].populate(
                    output,
                    shard,
                    event.channel,
                    temp,
                    R_4 as usize,
                );

                v0_outer[i] = v0_new;
                v1_outer[i] = v1_new;
                v2_outer[i] = v2_new;
                v3_outer[i] = v3_new;
            }

            // shuffle
            // v[1]
            v1_outer.swap(0, 3);
            v1_outer.swap(0, 1);
            v1_outer.swap(1, 2);

            // v[2]
            v2_outer.swap(0, 2);
            v2_outer.swap(1, 3);

            // v[3]
            v3_outer.swap(2, 3);
            v3_outer.swap(1, 2);
            v3_outer.swap(0, 1);

            // 3x (m2, R1, R2)
            for i in 0..4usize {
                cols.shuffled_indices[i + 4] = F::from_canonical_u32(1);
                cols.shuffled_indices[i + 8] = F::from_canonical_u32(1);
                cols.shuffled_indices[i + 12] = F::from_canonical_u32(1);

                let v0 = v0_outer[i];
                let v1 = v1_outer[i];
                let v2 = v2_outer[i];
                let v3 = v3_outer[i];
                let m3 = event.b_reads[i + 8].value;
                let zero1 = event.b_reads[i + 16].value;
                let zero2 = event.b_reads[i + 20].value;
                assert_eq!(zero1, 0);
                assert_eq!(zero2, 0);

                // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le());
                let v0_new =
                    cols.add[i + 16].populate(output, shard, event.channel, v0, v1, m3, zero1);
                assert_eq!(v0 + v1 + m3 + zero1, v0_new);

                // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
                let temp = cols.xor[i + 16].populate(output, shard, event.channel, v3, v0_new);
                let v3_new = cols.rotate_right[i + 16].populate(
                    output,
                    shard,
                    event.channel,
                    temp,
                    R_1 as usize,
                );
                assert_eq!((v3 ^ v0_new).rotate_right(R_1), v3_new);

                // v[2] = v[2].wrapping_add(v[3]);
                let v2_new = cols.add[i + 16 + 4].populate(
                    output,
                    shard,
                    event.channel,
                    v2,
                    v3_new,
                    zero1,
                    zero2,
                );
                assert_eq!(v2 + v3_new + zero1 + zero2, v2_new);

                // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
                let temp = cols.xor[i + 16 + 4].populate(output, shard, event.channel, v1, v2_new);
                let v1_new = cols.rotate_right[i + 16 + 4].populate(
                    output,
                    shard,
                    event.channel,
                    temp,
                    R_2 as usize,
                );
                assert_eq!((v1 ^ v2_new).rotate_right(R_2), v1_new);

                v0_outer[i] = v0_new;
                v1_outer[i] = v1_new;
                v2_outer[i] = v2_new;
                v3_outer[i] = v3_new;
            }

            // 4x (m3, R3, R4)
            for i in 0..4usize {
                let v0 = v0_outer[i];
                let v1 = v1_outer[i];
                let v2 = v2_outer[i];
                let v3 = v3_outer[i];
                let m4 = event.b_reads[i + 12].value;
                let zero1 = event.b_reads[i + 16].value;
                let zero2 = event.b_reads[i + 20].value;
                assert_eq!(zero1, 0);
                assert_eq!(zero2, 0);

                // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le()); (m2)
                let v0_new =
                    cols.add[i + 16 + 8].populate(output, shard, event.channel, v0, v1, m4, zero1);
                assert_eq!(v0 + v1 + m4 + zero1, v0_new);

                // v[3] = (v[3] ^ v[0]).rotate_right_const(rd); (R3)
                let temp = cols.xor[i + 16 + 8].populate(output, shard, event.channel, v3, v0_new);
                let v3_new = cols.rotate_right[i + 16 + 8].populate(
                    output,
                    shard,
                    event.channel,
                    temp,
                    R_3 as usize,
                );
                assert_eq!((v3 ^ v0_new).rotate_right(R_3), v3_new);

                // v[2] = v[2].wrapping_add(v[3]);
                let v2_new = cols.add[i + 16 + 4 + 8].populate(
                    output,
                    shard,
                    event.channel,
                    v2,
                    v3_new,
                    zero1,
                    zero2,
                );

                // v[1] = (v[1] ^ v[2]).rotate_right_const(rb); (R4)
                let temp =
                    cols.xor[i + 16 + 4 + 8].populate(output, shard, event.channel, v1, v2_new);
                let _v1_new = cols.rotate_right[i + 16 + 4 + 8].populate(
                    output,
                    shard,
                    event.channel,
                    temp,
                    R_4 as usize,
                );
            }
            rows.push(row);
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || {
            let row = vec![F::zero(); width];

            row
        });

        let mut trace =
            RowMajorMatrix::<F>::new(rows.into_iter().flatten().collect::<Vec<_>>(), width);

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut Blake2sRoundCols<F> =
                trace.values[i * width..(i + 1) * width].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.blake2s_round_events.is_empty()
    }
}
