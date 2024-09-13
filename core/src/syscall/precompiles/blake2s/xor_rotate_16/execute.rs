use super::Blake2sXorRotate16Chip;
use crate::{
    runtime::Syscall,
    syscall::precompiles::{blake2s::Blake2sXorRotate16Event, SyscallContext},
};

impl Syscall for Blake2sXorRotate16Chip {
    fn num_extra_cycles(&self) -> u32 {
        48
    }

    fn execute(&self, rt: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let clk_init = rt.clk;
        let w_ptr = arg1;
        assert!(arg2 == 0, "arg2 must be 0");

        let w_ptr_init = w_ptr;
        let mut w_0_reads = Vec::new();
        let mut w_1_reads = Vec::new();
        let mut w_2_reads = Vec::new();
        let mut w_3_reads = Vec::new();

        let mut w_4_reads = Vec::new();
        let mut w_5_reads = Vec::new();
        let mut w_6_reads = Vec::new();
        let mut w_7_reads = Vec::new();

        let mut w_16_writes = Vec::new();
        let mut w_17_writes = Vec::new();
        let mut w_18_writes = Vec::new();
        let mut w_19_writes = Vec::new();

        for _ in 16..64 {
            // read
            let (record, w_0) = rt.mr(w_ptr);
            w_0_reads.push(record);

            let (record, w_1) = rt.mr(w_ptr + 4);
            w_1_reads.push(record);

            let (record, w_2) = rt.mr(w_ptr + 8);
            w_2_reads.push(record);

            let (record, w_3) = rt.mr(w_ptr + 12);
            w_3_reads.push(record);

            let (record, w_4) = rt.mr(w_ptr + 16);
            w_4_reads.push(record);

            let (record, w_5) = rt.mr(w_ptr + 20);
            w_5_reads.push(record);

            let (record, w_6) = rt.mr(w_ptr + 24);
            w_6_reads.push(record);

            let (record, w_7) = rt.mr(w_ptr + 28);
            w_7_reads.push(record);

            // compute
            let w_16 = (w_0 ^ w_4).rotate_right(16);
            let w_17 = (w_1 ^ w_5).rotate_right(16);
            let w_18 = (w_2 ^ w_6).rotate_right(16);
            let w_19 = (w_3 ^ w_7).rotate_right(16);

            // write
            w_16_writes.push(rt.mw(w_ptr + 64, w_16));
            w_17_writes.push(rt.mw(w_ptr + 68, w_17));
            w_18_writes.push(rt.mw(w_ptr + 72, w_18));
            w_19_writes.push(rt.mw(w_ptr + 76, w_19));
            rt.clk += 1;
        }

        // Push the Blake2sXorRotate16Event event.
        let lookup_id = rt.syscall_lookup_id;
        let shard = rt.current_shard();
        let channel = rt.current_channel();
        rt.record_mut()
            .blake2s_xor_rotate_16_events
            .push(Blake2sXorRotate16Event {
                lookup_id,
                shard,
                channel,
                clk: clk_init,
                w_ptr: w_ptr_init,
                w_0_reads,
                w_1_reads,
                w_2_reads,
                w_3_reads,
                w_4_reads,
                w_5_reads,
                w_6_reads,
                w_7_reads,
                w_16_writes,
                w_17_writes,
                w_18_writes,
                w_19_writes,
            });

        None
    }
}
