//! `aead.rs`: Authenticated Encryption with Associated Data (AEAD):
//! Symmetric encryption which ensures message confidentiality, integrity,
//! and authenticity.

use aesni::{Aes128, Aes256};
use cmac::Cmac;
use core::marker::PhantomData;
use crypto_mac::Mac;
use ctr::{Aes128Ctr, Aes256Ctr, Ctr};
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

    /// Encrypt the contents of buffer in-place
    fn seal_in_place(&mut self, nonce: &[u8], associated_data: &[u8], buffer: &mut [u8]);

    /// Decrypt the contents of buffer in-place
    fn open_in_place<'a>(
        &mut self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], ()>;
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

    fn seal_in_place(&mut self, nonce: &[u8], associated_data: &[u8], buffer: &mut [u8]) {
        self.siv.seal_in_place(&[associated_data, nonce], buffer)
    }

    fn open_in_place<'a>(
        &mut self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], ()> {
        self.siv.open_in_place(&[associated_data, nonce], buffer)
    }
}
