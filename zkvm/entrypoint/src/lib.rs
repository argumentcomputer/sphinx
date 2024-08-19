pub mod heap;
pub mod syscalls;
pub mod io {
    pub use sphinx_precompiles::io::*;
}
pub mod precompiles {
    pub use sphinx_precompiles::*;
}

#[allow(unused_extern_crates)]
extern crate alloc;

#[macro_export]
macro_rules! entrypoint {
    ($path:path) => {
        const ZKVM_ENTRY: fn() = $path;

        use $crate::heap::SimpleAlloc;

        #[global_allocator]
        static HEAP: SimpleAlloc = SimpleAlloc;

        mod zkvm_generated_main {

            #[no_mangle]
            fn main() {
                super::ZKVM_ENTRY()
            }
        }
    };
}

#[cfg(all(target_os = "zkvm", feature = "libm"))]
mod libm;

/// The number of 32 bit words that the public values digest is composed of.
pub const PV_DIGEST_NUM_WORDS: usize = 8;
pub const POSEIDON_NUM_WORDS: usize = 8;

#[cfg(target_os = "zkvm")]
mod zkvm {
    use crate::syscalls::syscall_halt;

    use cfg_if::cfg_if;
    use getrandom::{register_custom_getrandom, Error};
    use sha2::{Digest, Sha256};

    cfg_if! {
        if #[cfg(feature = "verify")] {
            use p3_baby_bear::BabyBear;
            use p3_field::AbstractField;

            pub static mut DEFERRED_PROOFS_DIGEST: Option<[BabyBear; 8]> = None;
        }
    }

    pub static mut PUBLIC_VALUES_HASHER: Option<Sha256> = None;

    #[cfg(not(feature = "interface"))]
    #[no_mangle]
    unsafe extern "C" fn __start() {
        {
            PUBLIC_VALUES_HASHER = Some(Sha256::new());
            #[cfg(feature = "verify")]
            {
                DEFERRED_PROOFS_DIGEST = Some([BabyBear::zero(); 8]);
            }

            extern "C" {
                fn main();
            }
            main()
        }

        syscall_halt(0);
    }

    static STACK_TOP: u32 = 0x0020_0400;

    core::arch::global_asm!(include_str!("memset.s"));
    core::arch::global_asm!(include_str!("memcpy.s"));

    core::arch::global_asm!(
        r#"
    .section .text._start;
    .globl _start;
    _start:
        .option push;
        .option norelax;
        la gp, __global_pointer$;
        .option pop;
        la sp, {0}
        lw sp, 0(sp)
        call __start;
    "#,
        sym STACK_TOP
    );

    fn zkvm_getrandom(s: &mut [u8]) -> Result<(), Error> {
        unsafe {
            crate::syscalls::sys_rand(s.as_mut_ptr(), s.len());
        }

        Ok(())
    }

    register_custom_getrandom!(zkvm_getrandom);
}

//#![allow(clippy::assign_op_pattern)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use getset::Getters;
use sha2::{Digest, Sha512_256};
use uint::construct_uint;

construct_uint! {
    pub struct U256(4);
}

// Tag values can be found here:
// https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#chainweb-merkle-hash-function
const CHAIN_ID_TAG: u16 = 0x0002;
const BLOCK_HEIGHT_TAG: u16 = 0x0003;
const BLOCK_WEIGHT_TAG: u16 = 0x0004;
const FEATURE_FLAGS_TAG: u16 = 0x0006;
const BLOCK_CREATION_TIME_TAG: u16 = 0x0007;
const CHAINWEB_VERSION_TAG: u16 = 0x0008;
const HASH_TARGET_TAG: u16 = 0x0011;
const EPOCH_START_TIME_TAG: u16 = 0x0019;
const BLOCK_NONCE_TAG: u16 = 0x0020;

// Hash functions for Merkle tree nodes
// cf. https://github.com/kadena-io/chainweb-node/wiki/Chainweb-Merkle-Tree#merke-log-trees
pub type ChainwebHash = Sha512_256;

pub fn tag_bytes(tag: u16) -> [u8; 2] {
    tag.to_be_bytes()
}

pub fn hash_data(tag: u16, bytes: &[u8]) -> Vec<u8> {
    let x: &[u8] = &[0x0];
    ChainwebHash::digest([x, &tag_bytes(tag), bytes].concat().as_slice()).to_vec()
}

pub fn hash_root(bytes: &[u8; 32]) -> Vec<u8> {
    bytes.to_vec()
}

pub fn hash_inner(left: &[u8], right: &[u8]) -> Vec<u8> {
    let x: &[u8] = &[0x1];
    ChainwebHash::digest([x, left, right].concat().as_slice()).to_vec()
}

pub fn header_root(kadena_raw: &KadenaHeaderRaw) -> Vec<u8> {
    let header = KadenaHeader::from_raw(&kadena_raw.clone());
    let adjacents = header.adjacents().hashes();

    // Bottom leaves
    let hashes = vec![
        hash_data(FEATURE_FLAGS_TAG, kadena_raw.flags()),
        hash_data(BLOCK_CREATION_TIME_TAG, kadena_raw.time()),
        hash_root(kadena_raw.parent()),
        hash_data(HASH_TARGET_TAG, kadena_raw.target()),
        hash_root(kadena_raw.payload()),
        hash_data(CHAIN_ID_TAG, kadena_raw.chain()),
        hash_data(BLOCK_WEIGHT_TAG, kadena_raw.weight()),
        hash_data(BLOCK_HEIGHT_TAG, kadena_raw.height()),
        hash_data(CHAINWEB_VERSION_TAG, kadena_raw.version()),
        hash_data(EPOCH_START_TIME_TAG, kadena_raw.epoch_start()),
        hash_data(BLOCK_NONCE_TAG, kadena_raw.nonce()),
        hash_root(&adjacents[0]),
    ];
    // Hash bottom leaves pairs
    let mut intermediate_hashes = hashes
        .chunks(2)
        .map(|pair| hash_inner(&pair[0], &pair[1]))
        .collect::<Vec<_>>();

    // Include additional adjacent nodes at the correct level
    intermediate_hashes.push(hash_root(&adjacents[1]));
    intermediate_hashes.push(hash_root(&adjacents[2]));

    // Hash pairs of intermediate nodes until only one hash remains (the root)
    while intermediate_hashes.len() > 1 {
        intermediate_hashes = intermediate_hashes
            .chunks(2)
            .map(|pair| hash_inner(&pair[0], &pair[1]))
            .collect();
    }

    // The last remaining hash is the root
    intermediate_hashes[0].clone()
}

pub struct AdjacentParentRaw {
    chain: [u8; 4],
    hash: [u8; 32],
}

impl AdjacentParentRaw {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let chain: [u8; 4] = bytes[0..4].try_into().unwrap();
        let hash: [u8; 32] = bytes[4..36].try_into().unwrap();

        Self { chain, hash }
    }
}

#[derive(Debug)]
pub struct AdjacentParent {
    chain: u32,
    hash: [u8; 32],
}

impl AdjacentParent {
    pub fn from_raw(raw: &AdjacentParentRaw) -> Self {
        let chain = u32::from_le_bytes(raw.chain);
        let hash = raw.hash;

        Self { chain, hash }
    }
}

pub struct AdjacentParentRecordRaw {
    length: [u8; 2],
    adjacents: [u8; 108],
}

impl AdjacentParentRecordRaw {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let length: [u8; 2] = bytes[0..2].try_into().unwrap();
        let adjacents: [u8; 108] = bytes[2..110].try_into().unwrap();

        Self { length, adjacents }
    }
}

#[repr(align(1))]
#[derive(Debug)]
#[allow(dead_code)]
pub struct AdjacentParentRecord {
    length: u16,
    adjacents: [AdjacentParent; 3],
}

impl AdjacentParentRecord {
    pub fn from_raw(raw: &AdjacentParentRecordRaw) -> Self {
        let length = u16::from_le_bytes(raw.length);
        let mut adjacents = [
            AdjacentParent::from_raw(&AdjacentParentRaw::from_bytes(
                raw.adjacents[0..36].try_into().unwrap(),
            )),
            AdjacentParent::from_raw(&AdjacentParentRaw::from_bytes(
                raw.adjacents[36..72].try_into().unwrap(),
            )),
            AdjacentParent::from_raw(&AdjacentParentRaw::from_bytes(
                raw.adjacents[72..108].try_into().unwrap(),
            )),
        ];

        // just in case
        adjacents.sort_unstable_by_key(|v| v.chain);

        Self { length, adjacents }
    }

    pub fn hashes(&self) -> Vec<[u8; 32]> {
        self.adjacents.iter().map(|a| a.hash).collect()
    }
}

#[derive(Debug, Clone, Getters)]
#[getset(get = "pub")]
pub struct KadenaHeaderRaw {
    flags: [u8; 8],
    time: [u8; 8],
    parent: [u8; 32],
    adjacents: [u8; 110],
    target: [u8; 32],
    payload: [u8; 32],
    chain: [u8; 4],
    weight: [u8; 32],
    height: [u8; 8],
    version: [u8; 4],
    epoch_start: [u8; 8],
    nonce: [u8; 8],
    hash: [u8; 32],
}

#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct KadenaHeader {
    flags: [u8; 8], // All 0s, for future usage
    time: DateTime<Utc>,
    parent: U256,
    adjacents: AdjacentParentRecord,
    target: U256,
    payload: [u8; 32],
    chain: [u8; 4],
    weight: U256,
    height: u64,
    version: u32,
    epoch_start: DateTime<Utc>,
    nonce: [u8; 8],
    hash: [u8; 32],
}

impl KadenaHeader {
    pub fn from_raw(raw: &KadenaHeaderRaw) -> Self {
        let flags = raw.flags;
        let creation_time =
            DateTime::from_timestamp_micros(u64::from_le_bytes(raw.time) as i64).unwrap();
        let parent = U256::from_little_endian(&raw.parent);
        let adjacents =
            AdjacentParentRecord::from_raw(&AdjacentParentRecordRaw::from_bytes(&raw.adjacents));

        let target = U256::from_little_endian(&raw.target);
        let payload = raw.payload;
        let chain = raw.chain;
        let weight = U256::from_little_endian(&raw.weight);
        let height = u64::from_le_bytes(raw.height);
        let version = u32::from_le_bytes(raw.version);
        let epoch_start =
            DateTime::from_timestamp_micros(u64::from_le_bytes(raw.epoch_start) as i64).unwrap();
        let nonce = raw.nonce;
        let hash = raw.hash;

        Self {
            flags,
            time: creation_time,
            parent,
            adjacents,
            target,
            payload,
            chain,
            weight,
            height,
            version,
            epoch_start,
            nonce,
            hash,
        }
    }
}

impl KadenaHeaderRaw {
    pub fn from_base64(input: &[u8]) -> Self {
        let decoded = URL_SAFE_NO_PAD.decode(input).unwrap();

        let flags: [u8; 8] = decoded[0..8].try_into().unwrap();
        let time: [u8; 8] = decoded[8..16].try_into().unwrap();
        let parent: [u8; 32] = decoded[16..48].try_into().unwrap();
        let adjacents: [u8; 110] = decoded[48..158].try_into().unwrap();
        let target: [u8; 32] = decoded[158..190].try_into().unwrap();
        let payload: [u8; 32] = decoded[190..222].try_into().unwrap();
        let chain: [u8; 4] = decoded[222..226].try_into().unwrap();
        let weight: [u8; 32] = decoded[226..258].try_into().unwrap();
        let height: [u8; 8] = decoded[258..266].try_into().unwrap();
        let version: [u8; 4] = decoded[266..270].try_into().unwrap();
        let epoch_start: [u8; 8] = decoded[270..278].try_into().unwrap();
        let nonce: [u8; 8] = decoded[278..286].try_into().unwrap();
        let hash: [u8; 32] = decoded[286..318].try_into().unwrap();

        Self {
            flags,
            time,
            parent,
            adjacents,
            target,
            payload,
            chain,
            weight,
            height,
            version,
            epoch_start,
            nonce,
            hash,
        }
    }
}
