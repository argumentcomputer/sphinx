mod add_2;
mod add_3;
mod round;
mod xor_rotate_16; // based on sha-extend
mod xor_rotate_right_12;
mod xor_rotate_right_16;
mod xor_rotate_right_7;
mod xor_rotate_right_8;

pub use add_2::*;
pub use add_3::*;
pub use round::*;
pub use xor_rotate_16::*; // based on sha-extend
pub use xor_rotate_right_12::*;
pub use xor_rotate_right_16::*;
pub use xor_rotate_right_7::*;
pub use xor_rotate_right_8::*;

#[cfg(test)]
mod tests {
    fn xor_u32x4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
    }

    fn shuffle_left_1_u32x4(a: [u32; 4]) -> [u32; 4] {
        [a[1], a[2], a[3], a[0]]
    }

    fn shuffle_left_2_u32x4(a: [u32; 4]) -> [u32; 4] {
        [a[2], a[3], a[0], a[1]]
    }

    fn shuffle_left_3_u32x4(a: [u32; 4]) -> [u32; 4] {
        [a[3], a[0], a[1], a[2]]
    }

    fn shuffle_right_1_u32x4(a: [u32; 4]) -> [u32; 4] {
        shuffle_left_3_u32x4(a)
    }
    fn shuffle_right_2_u32x4(a: [u32; 4]) -> [u32; 4] {
        shuffle_left_2_u32x4(a)
    }
    fn shuffle_right_3_u32x4(a: [u32; 4]) -> [u32; 4] {
        shuffle_left_1_u32x4(a)
    }

    fn wrapping_add_u32x4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        [
            a[0].wrapping_add(b[0]),
            a[1].wrapping_add(b[1]),
            a[2].wrapping_add(b[2]),
            a[3].wrapping_add(b[3]),
        ]
    }

    fn rotate_right_const(a: [u32; 4], n: u32) -> [u32; 4] {
        [
            a[0].rotate_right(n),
            a[1].rotate_right(n),
            a[2].rotate_right(n),
            a[3].rotate_right(n),
        ]
    }

    fn quarter_round(v: &mut Vec<[u32; 4]>, rd: u32, rb: u32, m: [u32; 4]) {
        v[0] = wrapping_add_u32x4(wrapping_add_u32x4(v[0], v[1]), m); // m.from_le (?)
        v[3] = rotate_right_const(xor_u32x4(v[3], v[0]), rd);
        v[2] = wrapping_add_u32x4(v[2], v[3]);
        v[1] = rotate_right_const(xor_u32x4(v[1], v[2]), rb);
    }

    fn shuffle(v: &mut Vec<[u32; 4]>) {
        v[1] = shuffle_left_1_u32x4(v[1]);
        v[2] = shuffle_left_2_u32x4(v[2]);
        v[3] = shuffle_left_3_u32x4(v[3]);
    }

    fn unshuffle(v: &mut Vec<[u32; 4]>) {
        v[1] = shuffle_right_1_u32x4(v[1]);
        v[2] = shuffle_right_2_u32x4(v[2]);
        v[3] = shuffle_right_3_u32x4(v[3]);
    }

    fn gather(m: [u32; 16], i0: usize, i1: usize, i2: usize, i3: usize) -> [u32; 4] {
        [m[i0], m[i1], m[i2], m[i3]]
    }

    fn round(v: &mut Vec<[u32; 4]>, m: [u32; 16], s: [usize; 16]) {
        let r1 = 16;
        let r2 = 12;
        let r3 = 8;
        let r4 = 7;

        quarter_round(v, r1, r2, gather(m, s[0], s[2], s[4], s[6]));
        quarter_round(v, r3, r4, gather(m, s[1], s[3], s[5], s[7]));
        shuffle(v);
        quarter_round(v, r1, r2, gather(m, s[8], s[10], s[12], s[14]));
        quarter_round(v, r3, r4, gather(m, s[9], s[11], s[13], s[15]));
        unshuffle(v);
    }

    #[test]
    fn test_blake2s_round_function() {
        fn test_inner(
            input: &mut Vec<[u32; 4]>,
            m: [u32; 16],
            s: [usize; 16],
            output: Vec<[u32; 4]>,
        ) {
            round(input, m, s);
            assert_eq!(input.clone(), output);
        }

        let mut v: Vec<[u32; 4]> = vec![
            [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0xe07c2654, 0x5be0cd19],
        ];

        let m: [u32; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let s: [usize; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        test_inner(
            &mut v,
            m,
            s,
            vec![
                [0x82a01b5d, 0x248bd8f5, 0x1da4b59a, 0xb37b2bd3],
                [0x515f5af4, 0x0301095b, 0xb151a3c2, 0x5e17f96f],
                [0xc561666d, 0x0f291605, 0x990c6d13, 0x76fff6f1],
                [0x1e53bf19, 0x6fe4a680, 0x08e33663, 0x97fd885e],
            ],
        );

        let mut v: Vec<[u32; 4]> = vec![
            [0x01, 0x01, 0x01, 0x01],
            [0x01, 0x01, 0x01, 0x01],
            [0x01, 0x01, 0x01, 0x01],
            [0x01, 0x01, 0x01, 0x01],
        ];

        let m: [u32; 16] = [
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01,
        ];
        let s: [usize; 16] = [
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01,
        ];

        test_inner(
            &mut v,
            m,
            s,
            vec![
                [0x071e8a60, 0x071e8a60, 0x071e8a60, 0x071e8a60],
                [0x072df44c, 0x072df44c, 0x072df44c, 0x072df44c],
                [0x522ca035, 0x522ca035, 0x522ca035, 0x522ca035],
                [0x280137ec, 0x280137ec, 0x280137ec, 0x280137ec],
            ],
        );
    }

    #[test]
    fn test_blake2s_unshuffle_function() {
        let mut v: Vec<[u32; 4]> = vec![
            [0x82a01b5d, 0x248bd8f5, 0x1da4b59a, 0xb37b2bd3],
            [0x0301095b, 0xb151a3c2, 0x5e17f96f, 0x515f5af4],
            [0x990c6d13, 0x76fff6f1, 0xc561666d, 0x0f291605],
            [0x97fd885e, 0x1e53bf19, 0x6fe4a680, 0x08e33663],
        ];

        unshuffle(&mut v);

        assert_eq!(
            v[0].to_vec(),
            vec![0x82a01b5d, 0x248bd8f5, 0x1da4b59a, 0xb37b2bd3]
        );
        assert_eq!(
            v[1].to_vec(),
            vec![0x515f5af4, 0x0301095b, 0xb151a3c2, 0x5e17f96f]
        );
        assert_eq!(
            v[2].to_vec(),
            vec![0xc561666d, 0x0f291605, 0x990c6d13, 0x76fff6f1]
        );
        assert_eq!(
            v[3].to_vec(),
            vec![0x1e53bf19, 0x6fe4a680, 0x08e33663, 0x97fd885e]
        );
    }

    #[test]
    fn test_blake2s_shuffle_function() {
        let mut v: Vec<[u32; 4]> = vec![
            [0xdc0f959e, 0x8c871712, 0xc6a650d4, 0xd26fb9fc],
            [0x408705aa, 0x8d07c52d, 0xb9d6aa3a, 0x88609304],
            [0x5c7a89f8, 0xb5f896c7, 0x81e69eeb, 0xe17775ed],
            [0x87b6b678, 0x7af31ada, 0x5a2defeb, 0x2cdd25e3],
        ];

        shuffle(&mut v);

        assert_eq!(
            v[0].to_vec(),
            vec![0xdc0f959e, 0x8c871712, 0xc6a650d4, 0xd26fb9fc]
        );
        assert_eq!(
            v[1].to_vec(),
            vec![0x8d07c52d, 0xb9d6aa3a, 0x88609304, 0x408705aa]
        );
        assert_eq!(
            v[2].to_vec(),
            vec![0x81e69eeb, 0xe17775ed, 0x5c7a89f8, 0xb5f896c7]
        );
        assert_eq!(
            v[3].to_vec(),
            vec![0x2cdd25e3, 0x87b6b678, 0x7af31ada, 0x5a2defeb]
        );
    }

    #[test]
    fn test_blake2s_quarter_round_function() {
        let mut v: Vec<[u32; 4]> = vec![
            [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0xe07c2654, 0x5be0cd19],
        ];
        let m = [0, 0, 0, 0];
        let rd = 16;
        let rb = 12;

        quarter_round(&mut v, rd, rb, m);

        assert_eq!(
            v[0].to_vec(),
            vec![0xbc1738c6, 0x566d1711, 0x5bf2cd1d, 0x130c253]
        );
        assert_eq!(
            v[1].to_vec(),
            vec![0x1ff85cd8, 0x361a0001, 0x6ab383b7, 0xd13ef7a9]
        );
        assert_eq!(
            v[2].to_vec(),
            vec![0xd4c3d380, 0x3b057bed, 0x27b8af00, 0xb49a500a]
        );
        assert_eq!(
            v[3].to_vec(),
            vec![0x6ab9ed19, 0x7f9dcd68, 0xeb49bb8e, 0xf4a5ad0]
        );
    }

    #[test]
    fn test_blake2s_quarter_round_2x_function() {
        let mut v: Vec<[u32; 4]> = vec![
            [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0xe07c2654, 0x5be0cd19],
        ];
        let m = [0, 0, 0, 0];
        let rd = 16;
        let rb = 12;

        quarter_round(&mut v, rd, rb, m);

        let rd = 8;
        let rb = 7;

        quarter_round(&mut v, rd, rb, m);

        assert_eq!(
            v[0].to_vec(),
            vec![0xdc0f959e, 0x8c871712, 0xc6a650d4, 0xd26fb9fc]
        );
        assert_eq!(
            v[1].to_vec(),
            vec![0x408705aa, 0x8d07c52d, 0xb9d6aa3a, 0x88609304]
        );
        assert_eq!(
            v[2].to_vec(),
            vec![0x5c7a89f8, 0xb5f896c7, 0x81e69eeb, 0xe17775ed]
        );
        assert_eq!(
            v[3].to_vec(),
            vec![0x87b6b678, 0x7af31ada, 0x5a2defeb, 0x2cdd25e3]
        );
    }

    #[test]
    fn test_blake2s_quarter_round_2x_shuffle_function() {
        let mut v: Vec<[u32; 4]> = vec![
            [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0xe07c2654, 0x5be0cd19],
        ];
        let m = [0, 0, 0, 0];
        let rd = 16;
        let rb = 12;

        quarter_round(&mut v, rd, rb, m);

        let rd = 8;
        let rb = 7;

        quarter_round(&mut v, rd, rb, m);
        shuffle(&mut v);

        assert_eq!(
            v[0].to_vec(),
            vec![0xdc0f959e, 0x8c871712, 0xc6a650d4, 0xd26fb9fc]
        );
        assert_eq!(
            v[1].to_vec(),
            vec![0x8d07c52d, 0xb9d6aa3a, 0x88609304, 0x408705aa]
        );
        assert_eq!(
            v[2].to_vec(),
            vec![0x81e69eeb, 0xe17775ed, 0x5c7a89f8, 0xb5f896c7]
        );
        assert_eq!(
            v[3].to_vec(),
            vec![0x2cdd25e3, 0x87b6b678, 0x7af31ada, 0x5a2defeb]
        );
    }

    #[test]
    fn test_blake2s_quarter_round_2x_shuffle_quarter_round_2x_function() {
        let mut v: Vec<[u32; 4]> = vec![
            [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
            [0x510e527f, 0x9b05688c, 0xe07c2654, 0x5be0cd19],
        ];
        let m = [0, 0, 0, 0];
        let rd = 16;
        let rb = 12;
        quarter_round(&mut v, rd, rb, m);

        let rd = 8;
        let rb = 7;
        quarter_round(&mut v, rd, rb, m);
        shuffle(&mut v);

        let rd = 16;
        let rb = 12;
        quarter_round(&mut v, rd, rb, m);

        let rd = 8;
        let rb = 7;
        quarter_round(&mut v, rd, rb, m);
        unshuffle(&mut v);

        assert_eq!(
            v[0].to_vec(),
            vec![0x82a01b5d, 0x248bd8f5, 0x1da4b59a, 0xb37b2bd3]
        );
        assert_eq!(
            v[1].to_vec(),
            vec![0x515f5af4, 0x301095b, 0xb151a3c2, 0x5e17f96f]
        );
        assert_eq!(
            v[2].to_vec(),
            vec![0xc561666d, 0xf291605, 0x990c6d13, 0x76fff6f1]
        );
        assert_eq!(
            v[3].to_vec(),
            vec![0x1e53bf19, 0x6fe4a680, 0x8e33663, 0x97fd885e]
        );
    }
}
