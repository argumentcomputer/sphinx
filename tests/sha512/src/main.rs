#![no_main]
sphinx_zkvm::entrypoint!(main);

use hex_literal::hex;
use sha2::{Digest, Sha512_256};

pub fn main() {
    let data = vec![0x41u8; 4096];
    let hash = Sha512_256::digest(data);
    let mut ret = [0u8; 32];
    ret.copy_from_slice(&hash);
    println!("{}", hex::encode(ret));
    assert_eq!(
        ret,
        hex!("e2adb3b3eda0de7e5913c3cf8ada695b89ec3d79dcc6a23693b79172b0befa03")
    );
}
