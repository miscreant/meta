//! `ctr.rs`: Counter Mode encryption/decryption (128-bit IV size)
//!
//! TODO: this whole module is a legacy wrapper around aesni's former internal
//! AES-CTR implementation. We should really get rid of it and leverage the
//! `Ctr` types in the `block-modes` crate directly.

use aesni::{Aes128, Aes256, BlockCipher};
use aesni::block_cipher_trait::generic_array::{ArrayLength, GenericArray};
use aesni::block_cipher_trait::generic_array::typenum::consts::U16;
use block_modes::{BlockMode, BlockModeIv, Ctr128};
use block_modes::block_padding::ZeroPadding;
use clear_on_drop::clear::Clear;

/// Size of the initial counter value in bytes
pub const IV_SIZE: usize = 16;

/// Size of an AES block
const BLOCK_SIZE: usize = 16;

/// Common interface to counter mode encryption/decryption
pub trait Ctr<C>
where
    C: BlockCipher<BlockSize = U16>,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    /// Create a new CTR instance
    fn new(key: &[u8]) -> Self;

    /// Hax: Obtain a new cipher instance
    fn cipher(&self) -> C;

    /// XOR the CTR keystream into the given buffer
    fn xor_in_place(&self, iv: &[u8; IV_SIZE], buf: &mut [u8]) {
        let cipher = self.cipher();
        let mut ctr = Ctr128::<C, ZeroPadding>::new(cipher, &GenericArray::clone_from_slice(iv));

        let offset = buf.len() % BLOCK_SIZE;
        let aligned = buf.len() - offset;

        ctr.encrypt_nopad(&mut buf[..aligned]).unwrap();

        if offset != 0 {
            let mut block = [0u8; BLOCK_SIZE];
            ctr.encrypt_nopad(&mut block).unwrap();
            xor_in_place(&mut buf[aligned..], &block[..offset]);
        }
    }
}

/// AES-CTR with a 128-bit key
#[derive(Clone)]
pub struct Aes128Ctr {
    key: [u8; 16],
}

impl Ctr<Aes128> for Aes128Ctr {
    #[inline]
    fn new(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), 16, "expected 16-byte key, got {}", key.len());

        let mut k = [0u8; 16];
        k.copy_from_slice(key);

        Self { key: k }
    }

    #[inline]
    fn cipher(&self) -> Aes128 {
        Aes128::new_varkey(&self.key).unwrap()
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

impl Ctr<Aes256> for Aes256Ctr {
    #[inline]
    fn new(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), 32, "expected 32-byte key, got {}", key.len());

        let mut k = [0u8; 32];
        k.copy_from_slice(key);

        Self { key: k }
    }

    #[inline]
    fn cipher(&self) -> Aes256 {
        Aes256::new_varkey(&self.key).unwrap()
    }
}

impl Drop for Aes256Ctr {
    fn drop(&mut self) {
        self.key.clear()
    }
}

#[inline]
fn xor_in_place(a: &mut [u8], b: &[u8]) {
    for i in 0..b.len() {
        a[i] ^= b[i];
    }
}
