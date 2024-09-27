use super::Sha512ExtendChip;
use crate::{
    runtime::Syscall,
    syscall::precompiles::{sha512::Sha512ExtendEvent, SyscallContext},
};

impl Syscall for Sha512ExtendChip {
    fn num_extra_cycles(&self) -> u32 {
        0
    }

    fn execute(&self, rt: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let clk = rt.clk;
        let w_ptr = arg1;
        let i = arg2;
        assert!(i >= 16);
        assert!(i < 80);

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

        // Read w[i-15].
        let (w_i_minus_15_reads, w_i_minus_15) = rt.mr_slice(w_ptr + (i - 15) * 8, 2);
        let w_i_minus_15 = u32_vec_to_u64(w_i_minus_15);

        // Compute `s0`.
        let s0 = w_i_minus_15.rotate_right(1) ^ w_i_minus_15.rotate_right(8) ^ (w_i_minus_15 >> 7);

        // Read w[i-2].
        let (w_i_minus_2_reads, w_i_minus_2) = rt.mr_slice(w_ptr + (i - 2) * 8, 2);
        let w_i_minus_2 = u32_vec_to_u64(w_i_minus_2);

        // Compute `s1`.
        let s1 = w_i_minus_2.rotate_right(19) ^ w_i_minus_2.rotate_right(61) ^ (w_i_minus_2 >> 6);

        // Read w[i-16].
        let (w_i_minus_16_reads, w_i_minus_16) = rt.mr_slice(w_ptr + (i - 16) * 8, 2);
        let w_i_minus_16 = u32_vec_to_u64(w_i_minus_16);

        // Read w[i-7].
        let (w_i_minus_7_reads, w_i_minus_7) = rt.mr_slice(w_ptr + (i - 7) * 8, 2);
        let w_i_minus_7 = u32_vec_to_u64(w_i_minus_7);

        // Compute `w_i`.
        let w_i = s1
            .wrapping_add(w_i_minus_16)
            .wrapping_add(s0)
            .wrapping_add(w_i_minus_7);
        let w_i_bytes = w_i.to_le_bytes();
        let w_i_split = [
            u32::from_le_bytes(w_i_bytes[..4].try_into().unwrap()),
            u32::from_le_bytes(w_i_bytes[4..].try_into().unwrap()),
        ];

        // Write w[i].
        let w_i_writes = rt.mw_slice(w_ptr + i * 8, &w_i_split);

        // Push the SHA extend event.
        let lookup_id = rt.syscall_lookup_id;
        let shard = rt.current_shard();
        let channel = rt.current_channel();
        rt.record_mut()
            .sha512_extend_events
            .push(Sha512ExtendEvent {
                lookup_id,
                shard,
                channel,
                clk,
                w_ptr,
                i,
                w_i_minus_15_reads,
                w_i_minus_2_reads,
                w_i_minus_16_reads,
                w_i_minus_7_reads,
                w_i_writes,
            });

        None
    }
}
