//! `internals/aes.rs`: The Advanced Encryption Standard block cipher

use super::{Block, BlockCipher};

extern crate aesni;

use self::aesni::Aes128 as Aes128Ni;
use self::aesni::Aes256 as Aes256Ni;

/// AES with a 128-bit key
#[derive(Clone)]
pub struct Aes128 {
    cipher: Aes128Ni,
}

impl Aes128 {
    /// Create a new AES-128 cipher instance from the given key
    #[inline]
    pub fn new(key: &[u8; 16]) -> Self {
        Self { cipher: Aes128Ni::new(key) }
    }
}

impl BlockCipher for Aes128 {
    const KEY_SIZE: usize = 16;

    /// Encrypt an AES block in-place
    #[inline]
    fn encrypt(&self, block: &mut Block) {
        self.cipher.encrypt(block.as_mut())
    }
}

/// AES with a 256-bit key
#[derive(Clone)]
pub struct Aes256 {
    cipher: Aes256Ni,
}

impl Aes256 {
    /// Create a new AES-256 cipher instance from the given key
    #[inline]
    pub fn new(key: &[u8; 32]) -> Self {
        Self { cipher: Aes256Ni::new(key) }
    }
}

impl BlockCipher for Aes256 {
    const KEY_SIZE: usize = 32;

    /// Encrypt an AES block in-place
    #[inline]
    fn encrypt(&self, block: &mut Block) {
        self.cipher.encrypt(block.as_mut())
    }
}
