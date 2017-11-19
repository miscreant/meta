//! `internals/ctr.rs`: Counter Mode encryption/decryption

use super::{Block, BLOCK_SIZE};

extern crate aesni;

use self::aesni::CtrAes128 as CtrAesNi128;
use self::aesni::CtrAes256 as CtrAesNi256;

/// Common interface to counter mode encryption/decryption
pub trait Ctr {
    /// XOR the CTR keystream into the given buffer
    fn xor_in_place(&self, iv: &Block, buf: &mut [u8]);
}

/// AES-CTR with a 128-bit key
#[derive(Clone)]
pub struct Aes128Ctr {
    key: [u8; 16],
}

impl Aes128Ctr {
    /// Create a new AES-128-CTR instance from the given key
    #[inline]
    pub fn new(key: &[u8; 16]) -> Self {
        Self { key: *key }
    }
}

impl Ctr for Aes128Ctr {
    fn xor_in_place(&self, iv: &Block, buf: &mut [u8]) {
        let mut ctr = CtrAesNi128::new(&self.key, array_ref!(iv.as_ref(), 0, BLOCK_SIZE));
        ctr.xor(buf);
    }
}

/// AES-CTR with a 256-bit key
#[derive(Clone)]
pub struct Aes256Ctr {
    key: [u8; 32],
}

impl Aes256Ctr {
    /// Create a new AES-256-CTR instance from the given key
    #[inline]
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }
}

impl Ctr for Aes256Ctr {
    fn xor_in_place(&self, iv: &Block, buf: &mut [u8]) {
        let mut ctr = CtrAesNi256::new(&self.key, array_ref!(iv.as_ref(), 0, BLOCK_SIZE));
        ctr.xor(buf);
    }
}
