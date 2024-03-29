use std::borrow::BorrowMut;

use crate::stark::MachineRecord;
use p3_field::PrimeField32;
use p3_keccak_air::{generate_trace_rows, NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use tracing::instrument;

use crate::{air::MachineAir, runtime::ExecutionRecord};

use super::{
    columns::{KeccakMemCols, NUM_KECCAK_MEM_COLS},
    KeccakPermuteChip, STATE_SIZE,
};

impl<F: PrimeField32> MachineAir<F> for KeccakPermuteChip {
    type Record = ExecutionRecord;

    fn name(&self) -> String {
        "KeccakPermute".to_string()
    }

    #[instrument(name = "generate keccak permute trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let num_events = input.keccak_permute_events.len();
        let chunk_size = std::cmp::max(num_events / num_cpus::get(), 1);

        // Use par_chunks to generate the trace in parallel.
        let rows_and_records = (0..num_events)
            .collect::<Vec<_>>()
            .par_chunks(chunk_size)
            .map(|chunk| {
                let mut record = ExecutionRecord::default();
                let mut new_byte_lookup_events = Vec::new();

                // First generate all the p3_keccak_air traces at once.
                let perm_inputs = chunk
                    .iter()
                    .map(|event_index| input.keccak_permute_events[*event_index].pre_state)
                    .collect::<Vec<_>>();
                let mut p3_keccak_trace = generate_trace_rows::<F>(perm_inputs);

                let rows = chunk
                    .iter()
                    .enumerate()
                    .flat_map(|(index_in_chunk, event_index)| {
                        let mut rows = Vec::new();

                        let event = &input.keccak_permute_events[*event_index];
                        let start_clk = event.clk;
                        let shard = event.shard;

                        // Create all the rows for the permutation.
                        for i in 0..NUM_ROUNDS {
                            let p3_keccak_row =
                                p3_keccak_trace.row_mut(i + index_in_chunk * NUM_ROUNDS);
                            let mut row = [F::zero(); NUM_KECCAK_MEM_COLS];
                            // Copy p3_keccak_row into start of cols
                            row[..NUM_KECCAK_COLS].copy_from_slice(p3_keccak_row);
                            let cols: &mut KeccakMemCols<F> = row.as_mut_slice().borrow_mut();

                            cols.shard = F::from_canonical_u32(shard);
                            cols.clk = F::from_canonical_u32(start_clk);
                            cols.state_addr = F::from_canonical_u32(event.state_addr);
                            cols.is_real = F::one();

                            // If this is the first row, then populate read memory accesses
                            if i == 0 {
                                for (j, read_record) in event.state_read_records.iter().enumerate()
                                {
                                    cols.state_mem[j]
                                        .populate_read(*read_record, &mut new_byte_lookup_events);
                                }

                                cols.do_memory_check = F::one();
                                cols.receive_ecall = F::one();
                            }

                            // If this is the last row, then populate write memory accesses
                            if i == NUM_ROUNDS - 1 {
                                for (j, write_record) in
                                    event.state_write_records.iter().enumerate()
                                {
                                    cols.state_mem[j]
                                        .populate_write(*write_record, &mut new_byte_lookup_events);
                                }

                                cols.do_memory_check = F::one();
                            }

                            rows.push(row);
                        }
                        rows
                    })
                    .collect::<Vec<_>>();
                record.add_byte_lookup_events(new_byte_lookup_events);
                (rows, record)
            })
            .collect::<Vec<_>>();

        // Generate the trace rows for each event.
        let mut rows: Vec<[F; NUM_KECCAK_MEM_COLS]> = vec![];
        for (mut row, mut record) in rows_and_records {
            rows.append(&mut row);
            record.index = output.index;
            output.append(&mut record);
        }

        let nb_rows = rows.len();
        let mut padded_nb_rows = nb_rows.next_power_of_two();
        if padded_nb_rows == 2 || padded_nb_rows == 1 {
            padded_nb_rows = 4;
        }
        if padded_nb_rows > nb_rows {
            let mut dummy_keccak_rows = generate_trace_rows::<F>(vec![[0; STATE_SIZE]]);
            let mut dummy_rows = Vec::new();
            for i in 0..NUM_ROUNDS {
                let dummy_row = dummy_keccak_rows.row_mut(i);
                let mut row = [F::zero(); NUM_KECCAK_MEM_COLS];
                row[..NUM_KECCAK_COLS].copy_from_slice(dummy_row);
                dummy_rows.push(row);
            }
            rows.append(
                &mut dummy_rows
                    .iter()
                    .cloned()
                    .cycle()
                    .take(padded_nb_rows - nb_rows)
                    .collect::<Vec<_>>(),
            );
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_KECCAK_MEM_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.keccak_permute_events.is_empty()
    }
}
