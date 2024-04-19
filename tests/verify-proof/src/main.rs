#![no_main]
wp1_zkvm::entrypoint!(main);

use wp1_zkvm::precompiles::verify::verify_wp1_proof;

pub fn main() {
    let vkey = wp1_zkvm::io::read::<[u32; 8]>();
    let pv_digest = wp1_zkvm::io::read::<[u32; 8]>();

    verify_wp1_proof(&vkey, &pv_digest);
}
