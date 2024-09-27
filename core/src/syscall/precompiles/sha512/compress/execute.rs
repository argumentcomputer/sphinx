use super::Sha512CompressChip;
use crate::{
    runtime::Syscall,
    syscall::precompiles::{
        sha512::{Sha512CompressEvent, SHA512_COMPRESS_K},
        SyscallContext,
    },
};

impl Syscall for Sha512CompressChip {
    fn num_extra_cycles(&self) -> u32 {
        0
    }

    fn execute(&self, rt: &mut SyscallContext<'_, '_>, arg1: u32, arg2: u32) -> Option<u32> {
        let w_ptr = arg1;
        let h_ptr = arg2;
        assert_ne!(w_ptr, h_ptr);

        let start_clk = rt.clk;
        let mut h_write_records = Vec::new();

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

        // Execute the "initialize" phase where we read in the h values.
        let mut hx = [0u64; 8];
        for j in 0..8 {
            let values = rt.slice_unsafe(h_ptr + j * 8, 2);
            hx[j as usize] = u32_vec_to_u64(values);
        }

        // The `i` index is at the end of the `h_ptr` state
        let i = rt.word_unsafe(h_ptr + 8 * 8);
        assert!(i < 80);

        // The constants `k` are copied by the guest to the end of the state pointer
        let (k_i_read_records, k_i) = rt.mr_slice(h_ptr + (9 * 8) + i * 8, 2);
        let k_i = u32_vec_to_u64(k_i);
        assert_eq!(k_i, SHA512_COMPRESS_K[i as usize]);

        let (w_i_read_records, w_i) = rt.mr_slice(w_ptr + i * 8, 2);
        let w_i = u32_vec_to_u64(w_i);

        // Execute the "compress" iteration.
        let mut a = hx[0];
        let mut b = hx[1];
        let mut c = hx[2];
        let mut d = hx[3];
        let mut e = hx[4];
        let mut f = hx[5];
        let mut g = hx[6];
        let mut h = hx[7];

        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA512_COMPRESS_K[i as usize])
            .wrapping_add(w_i);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);

        // FIXME
        fn u64_to_u32x2(n: u64) -> [u32; 2] {
            let n = n.to_le_bytes();
            [
                u32::from_le_bytes(n[..4].try_into().unwrap()),
                u32::from_le_bytes(n[4..].try_into().unwrap()),
            ]
        }

        // Execute the "finalize" phase of updating the memory.
        let v = [a, b, c, d, e, f, g, h];
        let v: Vec<u32> = v.into_iter().flat_map(u64_to_u32x2).collect();
        for i in 0..16 {
            let record = rt.mw(h_ptr + i as u32 * 4, v[i]);
            h_write_records.push(record);
        }
        let i_write_record = rt.mw(h_ptr + 8 * 8, i.wrapping_add(1));

        // Push the SHA512 extend event.
        let lookup_id = rt.syscall_lookup_id;
        let shard = rt.current_shard();
        let channel = rt.current_channel();
        rt.record_mut()
            .sha512_compress_events
            .push(Sha512CompressEvent {
                lookup_id,
                shard,
                channel,
                clk: start_clk,
                w_ptr,
                h_ptr,
                w_i,
                i,
                k_i,
                h: hx,
                w_i_read_records: w_i_read_records.try_into().unwrap(),
                h_write_records: h_write_records.try_into().unwrap(),
                k_i_read_records: k_i_read_records.try_into().unwrap(),
                i_write_record,
            });

        None
    }
}
