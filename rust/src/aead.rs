//! `aead.rs`: Authenticated Encryption with Associated Data (AEAD):
//! Symmetric encryption which ensures message confidentiality, integrity,
//! and authenticity.

use ctr::IV_SIZE;
use siv::{self, Siv};

/// An AEAD algorithm
pub trait Algorithm {
    /// Size of a key associated with this AEAD algoritm
    const KEY_SIZE: usize;

    /// Size of a MAC tag
    const MAC_SIZE: usize;

    /// Create a new AEAD instance
    ///
    /// Panics if the key is the wrong length
    fn new(key: &[u8]) -> Self;

    /// Encrypt the contents of buffer in-place
    fn seal_in_place(&mut self, nonce: &[u8], associated_data: &[u8], buffer: &mut [u8]);

    /// Decrypt the contents of buffer in-place
    fn open_in_place<'a, I, T>(
        &mut self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], ()>;
}

/// Generate AEAD newtypes for SIV types
macro_rules! impl_siv_aead {
    ($name:ident, $key_size:expr, $doc:expr) => {
        #[doc=$doc]
        pub struct $name(siv::$name);

        impl Algorithm for $name {
            const KEY_SIZE: usize = $key_size;
            const MAC_SIZE: usize = IV_SIZE;

            fn new(key: &[u8]) -> Self {
                $name(Siv::new(key))
            }

            fn seal_in_place(&mut self, nonce: &[u8], associated_data: &[u8], buffer: &mut [u8]) {
                self.0.seal_in_place(&[associated_data, nonce], buffer)
            }

            fn open_in_place<'a, I, T>(
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
    16,
    "AES-CMAC-SIV in AEAD mode with 128-bit key size"
);

impl_siv_aead!(
    Aes256Siv,
    32,
    "AES-CMAC-SIV in AEAD mode with 256-bit key size"
);

impl_siv_aead!(
    Aes128PmacSiv,
    16,
    "AES-PMAC-SIV in AEAD mode with 128-bit key size"
);

impl_siv_aead!(
    Aes256PmacSiv,
    32,
    "AES-PMAC-SIV in AEAD mode with 256-bit key size"
);
