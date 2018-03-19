//! `aead.rs`: Authenticated Encryption with Associated Data (AEAD):
//! Symmetric encryption which ensures message confidentiality, integrity,
//! and authenticity.

use aesni::{Aes128, Aes256};
use aesni::block_cipher_trait::BlockCipher;
use aesni::block_cipher_trait::generic_array::{ArrayLength, GenericArray};
use aesni::block_cipher_trait::generic_array::typenum::{U16, U32, U64};
use cmac::Cmac;
use core::marker::PhantomData;
use crypto_mac::Mac;
use ctr::{Aes128Ctr, Aes256Ctr, Ctr};
#[cfg(feature = "std")]
use ctr::IV_SIZE;
use error::Error;
use pmac::Pmac;
use siv::Siv;

/// An AEAD algorithm
pub trait Algorithm {
    /// Size of a key associated with this AEAD algoritm
    type KeySize: ArrayLength<u8>;

    /// Size of a MAC tag
    type TagSize: ArrayLength<u8>;

    /// Create a new AEAD instance
    ///
    /// Panics if the key is the wrong length
    fn new(key: &[u8]) -> Self;

    /// Encrypt the given plaintext in-place, replacing it with the SIV tag and
    /// ciphertext. Requires a buffer with 16-bytes additional space.
    ///
    /// To encrypt data, it is recommended to use this API instead of the lower-level `Siv` API.
    ///
    /// # Usage
    ///
    /// It's important to note that only the *end* of the buffer will be
    /// treated as the input plaintext:
    ///
    /// ```rust
    /// let buffer = [0u8; 21];
    /// let plaintext = &buffer[..buffer.len() - 16];
    /// ```
    ///
    /// In this case, only the *last* 5 bytes are treated as the plaintext,
    /// since `21 - 16 = 5` (the AES block size is 16-bytes).
    ///
    /// The buffer must include an additional 16-bytes of space in which to
    /// write the SIV tag (at the beginning of the buffer).
    /// Failure to account for this will leave you with plaintext messages that
    /// are missing their first 16-bytes!
    ///
    /// # Panics
    ///
    /// Panics if `plaintext.len()` is less than `M::OutputSize`.
    /// Panics if `nonce.len()` is greater than `MAX_ASSOCIATED_DATA`.
    /// Panics if `associated_data.len()` is greater than `MAX_ASSOCIATED_DATA`.
    fn seal_in_place(&mut self, nonce: &[u8], associated_data: &[u8], buffer: &mut [u8]);

    /// Decrypt the given ciphertext in-place, authenticating it against the
    /// synthetic IV included in the message.
    ///
    /// To decrypt data, it is recommended to use this API instead of the lower-level `Siv` API.
    ///
    /// Returns a slice containing a decrypted message on success.
    fn open_in_place<'a>(
        &mut self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], Error>;

    /// Encrypt the given plaintext, allocating and returning a Vec<u8> for the ciphertext
    #[cfg(feature = "std")]
    fn seal(&mut self, nonce: &[u8], associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut buffer = vec![0; IV_SIZE + plaintext.len()];
        buffer[IV_SIZE..].copy_from_slice(plaintext);
        self.seal_in_place(nonce, associated_data, &mut buffer);
        buffer
    }

    /// Decrypt the given ciphertext, allocating and returning a Vec<u8> for the plaintext
    #[cfg(feature = "std")]
    fn open(
        &mut self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::from(ciphertext);
        self.open_in_place(nonce, associated_data, &mut buffer)?;
        buffer.drain(..IV_SIZE);
        Ok(buffer)
    }
}

/// AEAD interface provider for AES-(PMAC-)SIV types
pub struct SivAlgorithm<B, C, M, K>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    C: Ctr<B>,
    M: Mac<OutputSize = U16>,
    K: ArrayLength<u8>,
{
    block_cipher: PhantomData<B>,
    siv: Siv<B, C, M>,
    key_size: PhantomData<K>,
}

/// AES-CMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
pub type Aes128Siv = SivAlgorithm<Aes128, Aes128Ctr, Cmac<Aes128>, U32>;

/// AES-CMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
pub type Aes256Siv = SivAlgorithm<Aes256, Aes256Ctr, Cmac<Aes256>, U64>;

/// AES-PMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
pub type Aes128PmacSiv = SivAlgorithm<Aes128, Aes128Ctr, Pmac<Aes128>, U32>;

/// AES-PMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
pub type Aes256PmacSiv = SivAlgorithm<Aes256, Aes256Ctr, Pmac<Aes256>, U64>;

impl<B, C, M, K> Algorithm for SivAlgorithm<B, C, M, K>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    C: Ctr<B>,
    M: Mac<OutputSize = U16>,
    K: ArrayLength<u8>,
{
    type KeySize = K;
    type TagSize = U16;

    fn new(key: &[u8]) -> Self {
        Self {
            block_cipher: PhantomData,
            siv: Siv::new(key),
            key_size: PhantomData,
        }
    }

    fn seal_in_place(&mut self, nonce: &[u8], associated_data: &[u8], buffer: &mut [u8]) {
        self.siv.seal_in_place(&[associated_data, nonce], buffer)
    }

    fn open_in_place<'a>(
        &mut self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.siv.open_in_place(&[associated_data, nonce], buffer)
    }
}
