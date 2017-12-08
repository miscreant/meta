//! `aead.rs`: Authenticated Encryption with Associated Data (AEAD):
//! Symmetric encryption which ensures message confidentiality, integrity,
//! and authenticity.

use aesni::{Aes128, Aes256};
use buffer::Buffer;
use cmac::Cmac;
use core::marker::PhantomData;
use crypto_mac::Mac;
use ctr::{Aes128Ctr, Aes256Ctr, Ctr};
use error::Error;
use generic_array::ArrayLength;
use generic_array::typenum::{U16, U32, U64};
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

    /// Encrypt the contents of buf in-place
    fn seal_in_place<B>(&mut self, nonce: &[u8], associated_data: &[u8], buf: &mut Buffer<B>)
    where
        B: AsRef<[u8]> + AsMut<[u8]>;

    /// Decrypt the contents of buf in-place
    fn open_in_place<B>(
        &mut self,
        nonce: &[u8],
        associated_data: &[u8],
        buf: &mut Buffer<B>,
    ) -> Result<(), Error>
    where
        B: AsRef<[u8]> + AsMut<[u8]>;

    /// Encrypt the given plaintext, allocating and returning a Vec<u8> for the ciphertext
    #[cfg(feature = "std")]
    fn seal(&mut self, nonce: &[u8], associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut buf = Buffer::from_plaintext(plaintext);
        self.seal_in_place(nonce, associated_data, &mut buf);
        buf.into_contents()
    }

    /// Decrypt the given ciphertext, allocating and returning a Vec<u8> for the plaintext
    #[cfg(feature = "std")]
    fn open(
        &mut self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut buf = Buffer::from(Vec::from(ciphertext));
        self.open_in_place(nonce, associated_data, &mut buf)?;
        Ok(buf.into_plaintext())
    }
}

/// AEAD interface provider for AES-(PMAC-)SIV types
pub struct SivAlgorithm<C: Ctr, M: Mac<OutputSize = U16>, K: ArrayLength<u8>> {
    siv: Siv<C, M>,
    key_size: PhantomData<K>,
}

/// AES-CMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
pub type Aes128Siv = SivAlgorithm<Aes128Ctr, Cmac<Aes128>, U32>;

/// AES-CMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
pub type Aes256Siv = SivAlgorithm<Aes256Ctr, Cmac<Aes256>, U64>;

/// AES-PMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
pub type Aes128PmacSiv = SivAlgorithm<Aes128Ctr, Pmac<Aes128>, U32>;

/// AES-PMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
pub type Aes256PmacSiv = SivAlgorithm<Aes256Ctr, Pmac<Aes256>, U64>;

impl<C, M, K> Algorithm for SivAlgorithm<C, M, K>
where
    C: Ctr,
    M: Mac<OutputSize = U16>,
    K: ArrayLength<u8>,
{
    type KeySize = K;
    type TagSize = U16;

    fn new(key: &[u8]) -> Self {
        Self {
            siv: Siv::new(key),
            key_size: PhantomData,
        }
    }

    fn seal_in_place<B>(&mut self, nonce: &[u8], associated_data: &[u8], buf: &mut Buffer<B>)
    where
        B: AsRef<[u8]> + AsMut<[u8]>,
    {
        self.siv.seal_in_place(&[associated_data, nonce], buf)
    }

    fn open_in_place<B>(
        &mut self,
        nonce: &[u8],
        associated_data: &[u8],
        buf: &mut Buffer<B>,
    ) -> Result<(), Error>
    where
        B: AsRef<[u8]> + AsMut<[u8]>,
    {
        self.siv.open_in_place(&[associated_data, nonce], buf)
    }
}
