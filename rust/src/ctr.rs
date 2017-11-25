//! `internals/ctr.rs`: Counter Mode encryption/decryption (128-bit IV size)

use aesni::CtrAes128 as CtrAesNi128;
use aesni::CtrAes256 as CtrAesNi256;
use clear_on_drop::clear::Clear;

/// Size of the initial counter value in bytes
pub const IV_SIZE: usize = 16;

/// Common interface to counter mode encryption/decryption
pub trait Ctr {
    /// Create a new CTR instance
    fn new(key: &[u8]) -> Self;

    /// XOR the CTR keystream into the given buffer
    fn xor_in_place(&self, iv: &[u8; IV_SIZE], buf: &mut [u8]);
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

        let mut k = [0u8; 16];
        k.copy_from_slice(key);

        Self { key: k }
    }

    fn xor_in_place(&self, iv: &[u8; IV_SIZE], buf: &mut [u8]) {
        CtrAesNi128::new(&self.key, iv).xor(buf);
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
        debug_assert_eq!(key.len(), 32, "expected 32-byte key, got {}", key.len());

        let mut k = [0u8; 32];
        k.copy_from_slice(key);

        Self { key: k }
    }

    fn xor_in_place(&self, iv: &[u8; IV_SIZE], buf: &mut [u8]) {
        CtrAesNi256::new(&self.key, iv).xor(buf);
    }
}

impl Drop for Aes256Ctr {
    fn drop(&mut self) {
        self.key.clear()
    }
}
