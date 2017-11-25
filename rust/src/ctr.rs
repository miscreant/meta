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
    /// Create a new CTR instance
    fn new(key: &[u8]) -> Self;

    /// XOR the CTR keystream into the given buffer
    fn xor_in_place(&self, iv: &Iv, buf: &mut [u8]);
}

/// AES-CTR with a 128-bit key
#[derive(Clone)]
pub struct Aes128Ctr {
    key: [u8; 16],
}

impl Ctr for Aes128Ctr {
    #[inline]
    fn new(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), 16, "expected 16-byte key, got {}", key.len());
        Self { key: *array_ref!(key, 0, 16) }
    }

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

impl Ctr for Aes256Ctr {
    #[inline]
    fn new(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), 32, "expected 16-byte key, got {}", key.len());
        Self { key: *array_ref!(key, 0, 32) }
    }

    fn xor_in_place(&self, iv: &Iv, buf: &mut [u8]) {
        CtrAesNi256::new(&self.key, array_ref!(iv, 0, 16)).xor(buf);
    }
}

impl Drop for Aes256Ctr {
    fn drop(&mut self) {
        self.key.clear()
    }
}
