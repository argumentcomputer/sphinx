use crate::runtime::{Syscall, SyscallContext};
use crate::syscall::precompiles::blake2s::{
    Blake2sRoundChip, Blake2sRoundEvent, R_1, R_2, R_3, R_4,
};

impl Syscall for Blake2sRoundChip {
    fn execute(&self, ctx: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let clk_init = ctx.clk;
        let shard = ctx.current_shard();
        let lookup_id = ctx.syscall_lookup_id;
        let channel = ctx.current_channel();

        let a_ptr = arg1;
        let b_ptr = arg2;

        let mut a = ctx.slice_unsafe(a_ptr, 16);
        let mut a_clone = a.clone();

        let (b_reads, b) = ctx.mr_slice(b_ptr, 16);

        // 1x (m0, R1, R2)
        // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le()); (m1)
        for ((v0, v1), m) in a[0..4]
            .iter_mut()
            .zip(a_clone[4..8].iter())
            .zip(b[0..4].iter())
        {
            *v0 = (*v0).wrapping_add(*v1).wrapping_add(*m);
        }
        a_clone = a.clone();

        // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
        for (v3, v0) in a[12..16].iter_mut().zip(a_clone[0..4].iter()) {
            *v3 = (*v3 ^ *v0).rotate_right(R_1);
        }
        a_clone = a.clone();

        // v[2] = v[2].wrapping_add(v[3]);
        for (v2, v3) in a[8..12].iter_mut().zip(a_clone[12..16].iter()) {
            *v2 = (*v2).wrapping_add(*v3);
        }
        a_clone = a.clone();

        // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
        for (v1, v2) in a[4..8].iter_mut().zip(a_clone[8..12].iter()) {
            *v1 = (*v1 ^ *v2).rotate_right(R_2);
        }

        // 2x (m1, R3, R4)
        let mut a = a.clone(); // a after 1x quarter_round
        let mut a_clone = a.clone();

        // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le()); (m2)
        for ((v0, v1), m) in a[0..4]
            .iter_mut()
            .zip(a_clone[4..8].iter())
            .zip(b[4..8].iter())
        {
            *v0 = (*v0).wrapping_add(*v1).wrapping_add(*m);
        }
        a_clone = a.clone();

        // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
        for (v3, v0) in a[12..16].iter_mut().zip(a_clone[0..4].iter()) {
            *v3 = (*v3 ^ *v0).rotate_right(R_3);
        }
        a_clone = a.clone();

        // v[2] = v[2].wrapping_add(v[3]);
        for (v2, v3) in a[8..12].iter_mut().zip(a_clone[12..16].iter()) {
            *v2 = (*v2).wrapping_add(*v3);
        }
        a_clone = a.clone();

        // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
        for (v1, v2) in a[4..8].iter_mut().zip(a_clone[8..12].iter()) {
            *v1 = (*v1 ^ *v2).rotate_right(R_4);
        }

        // shuffle
        // v[1]
        a[4..8].swap(0, 3);
        a[4..8].swap(0, 1);
        a[4..8].swap(1, 2);

        // v[2]
        a[8..12].swap(0, 2);
        a[8..12].swap(1, 3);

        // v[3]
        a[12..16].swap(2, 3);
        a[12..16].swap(1, 2);
        a[12..16].swap(0, 1);

        let mut a = a.clone(); // a after 2x quarter_round
        let mut a_clone = a.clone();

        // 3x (m2, R1, R2)
        // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le()); (m3)
        for ((v0, v1), m) in a[0..4]
            .iter_mut()
            .zip(a_clone[4..8].iter())
            .zip(b[8..12].iter())
        {
            *v0 = (*v0).wrapping_add(*v1).wrapping_add(*m);
        }
        a_clone = a.clone();

        // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
        for (v3, v0) in a[12..16].iter_mut().zip(a_clone[0..4].iter()) {
            *v3 = (*v3 ^ *v0).rotate_right(R_1);
        }
        a_clone = a.clone();

        // v[2] = v[2].wrapping_add(v[3]);
        for (v2, v3) in a[8..12].iter_mut().zip(a_clone[12..16].iter()) {
            *v2 = (*v2).wrapping_add(*v3);
        }
        a_clone = a.clone();

        // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
        for (v1, v2) in a[4..8].iter_mut().zip(a_clone[8..12].iter()) {
            *v1 = (*v1 ^ *v2).rotate_right(R_2);
        }

        // 4x (m3, R3, R4)
        let mut a = a.clone(); // a after 3x quarter_round
        let mut a_clone = a.clone();

        // v[0] = v[0].wrapping_add(v[1]).wrapping_add(m.from_le()); (m2)
        for ((v0, v1), m) in a[0..4]
            .iter_mut()
            .zip(a_clone[4..8].iter())
            .zip(b[12..16].iter())
        {
            *v0 = (*v0).wrapping_add(*v1).wrapping_add(*m);
        }
        a_clone = a.clone();

        // v[3] = (v[3] ^ v[0]).rotate_right_const(rd);
        for (v3, v0) in a[12..16].iter_mut().zip(a_clone[0..4].iter()) {
            *v3 = (*v3 ^ *v0).rotate_right(R_3);
        }
        a_clone = a.clone();

        // v[2] = v[2].wrapping_add(v[3]);
        for (v2, v3) in a[8..12].iter_mut().zip(a_clone[12..16].iter()) {
            *v2 = (*v2).wrapping_add(*v3);
        }
        a_clone = a.clone();

        // v[1] = (v[1] ^ v[2]).rotate_right_const(rb);
        for (v1, v2) in a[4..8].iter_mut().zip(a_clone[8..12].iter()) {
            *v1 = (*v1 ^ *v2).rotate_right(R_4);
        }

        // unshuffle
        // v[1]
        a[4..8].swap(2, 3);
        a[4..8].swap(1, 2);
        a[4..8].swap(0, 1);

        // v[2]
        a[8..12].swap(0, 2);
        a[8..12].swap(1, 3);

        // v[3]
        a[12..16].swap(0, 3);
        a[12..16].swap(0, 1);
        a[12..16].swap(1, 2);

        ctx.clk += 1;

        // Write rotate_right to a_ptr.
        let a_reads_writes = ctx.mw_slice(a_ptr, a.as_slice());

        ctx.record_mut()
            .blake2s_round_events
            .push(Blake2sRoundEvent {
                lookup_id,
                clk: clk_init,
                shard,
                channel,
                a_ptr,
                b_ptr,
                a_reads_writes,
                b_reads,
            });

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
