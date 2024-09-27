#![no_main]
sphinx_zkvm::entrypoint!(main);

use sphinx_zkvm::syscalls::syscall_sha512_extend;

pub fn main() {
    let mut w = [1u64; 64];
    for i in 16..80 {
        syscall_sha512_extend(w.as_mut_ptr(), i);
    }
    println!("{:?}", w);
}
