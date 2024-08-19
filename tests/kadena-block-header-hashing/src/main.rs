#![no_main]

use sphinx_zkvm::{ KadenaHeaderRaw, header_root };

sphinx_zkvm::entrypoint!(main);

pub fn main() {
    let header_bytes_base64 = sphinx_zkvm::io::read::<Vec<u8>>();
    let header = KadenaHeaderRaw::from_base64(&header_bytes_base64);
    let actual = header_root(&header);
    assert_eq!(actual, header.hash());
    sphinx_zkvm::io::commit(&actual);
}
