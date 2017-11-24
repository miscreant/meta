//! `internals/ctr.rs`: Counter Mode encryption/decryption (128-bit IV size)

use aesni::CtrAes128 as CtrAesNi128;
use aesni::CtrAes256 as CtrAesNi256;
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::U16;
use clear_on_drop::clear::Clear;

/// Size of the initial counter value in bytes
pub const IV_SIZE: usize = 16;

/// Initial counter value (a.k.a. initialization vector or IV)
pub type Iv = GenericArray<u8, U16>;

/// Common interface to counter mode encryption/decryption
pub trait Ctr {
    /// XOR the CTR keystream into the given buffer
    fn xor_in_place(&self, iv: &Iv, buf: &mut [u8]);
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
    fn xor_in_place(&self, iv: &Iv, buf: &mut [u8]) {
        CtrAesNi128::new(&self.key, array_ref!(iv, 0, 16)).xor(buf);
    }
}

impl Drop for Aes128Ctr {
    fn drop(&mut self) {
        self.key.clear()
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
    fn xor_in_place(&self, iv: &Iv, buf: &mut [u8]) {
        CtrAesNi256::new(&self.key, array_ref!(iv, 0, 16)).xor(buf);
    }
}

impl Drop for Aes256Ctr {
    fn drop(&mut self) {
        self.key.clear()
    }
}
