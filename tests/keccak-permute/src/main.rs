#![no_main]
wp1_zkvm::entrypoint!(main);

use wp1_zkvm::syscalls::syscall_keccak_permute;

pub fn main() {
    for _ in 0..25 {
        let mut state = [1u64; 25];
        syscall_keccak_permute(state.as_mut_ptr());
        println!("{:?}", state);
    }
}
