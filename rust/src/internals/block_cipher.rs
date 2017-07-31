//! `internals/block_cipher.rs`: Trait for encrypting with different block ciphers.

use super::Block;

/// Common interface to a block cipher's raw block function
///
/// We implement only the encryption function as that's all that AES-SIV depends on
pub trait BlockCipher: Clone {
    /// Size of the key used by this cipher (in bytes)
    const KEY_SIZE: usize;

    /// Encrypt a block
    fn encrypt(&self, block: &mut Block);
}
