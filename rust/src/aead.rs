//! `aead.rs`: Authenticated Encryption with Associated Data (AEAD):
//! Symmetric encryption which ensures message confidentiality, integrity,
//! and authenticity.

use generic_array::ArrayLength;
use generic_array::typenum::{U16, U32, U64};
use siv::{self, Siv};

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

/// Generate AEAD newtypes for SIV types
macro_rules! impl_siv_aead {
    ($name:ident, $key_size:ty, $doc:expr) => {
        #[doc=$doc]
        pub struct $name(siv::$name);

        impl Algorithm for $name {
            type KeySize = $key_size;
            type TagSize = U16;

            fn new(key: &[u8]) -> Self {
                $name(Siv::new(key))
            }

            fn seal_in_place(&mut self, nonce: &[u8], associated_data: &[u8], buffer: &mut [u8]) {
                self.0.seal_in_place(&[associated_data, nonce], buffer)
            }

            fn open_in_place<'a>(
                &mut self,
                nonce: &[u8],
                associated_data: &[u8],
                buffer: &'a mut [u8],
            ) -> Result<&'a [u8], ()> {
                self.0.open_in_place(&[associated_data, nonce], buffer)
            }
        }
    }
}

impl_siv_aead!(
    Aes128Siv,
    U32,
    "AES-CMAC-SIV in AEAD mode with 256-bit key size (128-bit security)"
);

impl_siv_aead!(
    Aes256Siv,
    U64,
    "AES-CMAC-SIV in AEAD mode with 512-bit key size (256-bit security)"
);

impl_siv_aead!(
    Aes128PmacSiv,
    U32,
    "AES-PMAC-SIV in AEAD mode with 256-bit key size (128-bit security"
);

impl_siv_aead!(
    Aes256PmacSiv,
    U64,
    "AES-PMAC-SIV in AEAD mode with 512-bit key size (256-bit security)"
);
