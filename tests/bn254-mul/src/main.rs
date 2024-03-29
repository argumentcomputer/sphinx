#![no_main]
wp1_zkvm::entrypoint!(main);

use wp1_zkvm::precompiles::bn254::Bn254;
use wp1_zkvm::precompiles::utils::AffinePoint;

#[wp1_derive::cycle_tracker]
pub fn main() {
    // generator.
    // 1
    // 2
    let a: [u8; 64] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    let mut a_point = AffinePoint::<Bn254>::from_le_bytes(a);

    // scalar.
    // 3
    let scalar: [u32; 8] = [3, 0, 0, 0, 0, 0, 0, 0];

    println!("cycle-tracker-start: bn254_mul");
    a_point.mul_assign(&scalar);
    println!("cycle-tracker-end: bn254_mul");

    // 3 * generator.
    // 3353031288059533942658390886683067124040920775575537747144343083137631628272
    // 19321533766552368860946552437480515441416830039777911637913418824951667761761
    let c: [u8; 64] = [
        240, 171, 21, 25, 150, 85, 211, 242, 121, 230, 184, 21, 71, 216, 21, 147, 21, 189, 182,
        177, 188, 50, 2, 244, 63, 234, 107, 197, 154, 191, 105, 7, 97, 34, 254, 217, 61, 255, 241,
        205, 87, 91, 156, 11, 180, 99, 158, 49, 117, 100, 8, 141, 124, 219, 79, 85, 41, 148, 72,
        224, 190, 153, 183, 42,
    ];

    assert_eq!(a_point.to_le_bytes(), c);

    println!("done");
}
