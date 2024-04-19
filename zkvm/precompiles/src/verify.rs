use crate::syscall_verify_wp1_proof;

pub fn verify_wp1_proof(commitment: &[u32; 8], pv_digest: &[u32; 8]) {
    unsafe {
        syscall_verify_wp1_proof(commitment, pv_digest);
    }
}
