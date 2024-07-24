#![no_main]
sphinx_zkvm::entrypoint!(main);

use hybrid_array::typenum::U16;
use sphinx_zkvm::precompiles::secp256k1::Secp256k1Operations;
use sphinx_zkvm::precompiles::utils::AffinePoint;

#[sphinx_derive::cycle_tracker]
pub fn main() {
    for _ in 0..4 {
        // generator.
        // 55066263022277343669578718895168534326250603453777594175500187360389116729240
        // 32670510020758816978083085130507043184471273380659243275938904335757337482424
        let a: [u8; 64] = [
            152, 23, 248, 22, 91, 129, 242, 89, 217, 40, 206, 45, 219, 252, 155, 2, 7, 11, 135,
            206, 149, 98, 160, 85, 172, 187, 220, 249, 126, 102, 190, 121, 184, 212, 16, 251, 143,
            208, 71, 156, 25, 84, 133, 166, 72, 180, 23, 253, 168, 8, 17, 14, 252, 251, 164, 93,
            101, 196, 163, 38, 119, 218, 58, 72,
        ];

<<<<<<< HEAD
        let mut a_point = AffinePoint::<Secp256k1Operations, U16>::from_le_bytes(&a);
||||||| parent of 642efdd62 (feat: catch-up to testnet v1.0.7)
    let mut a_point = AffinePoint::<Secp256k1Operations, 16>::from_le_bytes(&a);
=======
        let mut a_point = AffinePoint::<Secp256k1Operations, 16>::from_le_bytes(&a);
>>>>>>> 642efdd62 (feat: catch-up to testnet v1.0.7)

        // scalar.
        // 3
        let scalar: [u32; 8] = [3, 0, 0, 0, 0, 0, 0, 0];

        println!("cycle-tracker-start: secp256k1_mul");
        a_point.mul_assign(&scalar);
        println!("cycle-tracker-end: secp256k1_mul");

        // 3 * generator.
        // 112711660439710606056748659173929673102114977341539408544630613555209775888121
        // 25583027980570883691656905877401976406448868254816295069919888960541586679410
        let c: [u8; 64] = [
            249, 54, 224, 188, 19, 241, 1, 134, 176, 153, 111, 131, 69, 200, 49, 181, 41, 82, 157,
            248, 133, 79, 52, 73, 16, 195, 88, 146, 1, 138, 48, 249, 114, 230, 184, 132, 117, 253,
            185, 108, 27, 35, 194, 52, 153, 169, 0, 101, 86, 243, 55, 42, 230, 55, 227, 15, 20,
            232, 45, 99, 15, 123, 143, 56,
        ];

        assert_eq!(a_point.to_le_bytes(), c);
    }

    println!("done");
}
