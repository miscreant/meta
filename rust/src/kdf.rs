//! `kdf.rs`: Key Derivation Function
//!
//! WARNING: The code contained in this module is EXPERIMENTAL and should
//! NOT be used until this warning is removed.

use clear_on_drop::clear::Clear;
use crypto_mac::Mac;
use ctr::{Aes128Ctr, Aes256Ctr, Ctr, IV_SIZE};
use digest::XofReader;
use generic_array::GenericArray;
use generic_array::typenum::U16;
use s2v::s2v;

/// EXPERIMENTAL key derivation function. DO NOT USE!!!
pub struct Kdf<C: Ctr> {
    ctr: C,
    finished: bool
}

/// AES-CMAC KDF with a 128-bit key
pub type Aes128Kdf = Kdf<Aes128Ctr>;

/// AES-PMAC KDF with a 256-bit key
pub type Aes256Kdf = Kdf<Aes256Ctr>;

impl<C: Ctr> Kdf<C> {
    /// Create a new KDF instance
    ///
    /// Panics if input key material is not the same length as the MAC
    /// function's key size
    pub fn new<M: Mac<OutputSize = U16>>(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Self {
        let mut mac = M::new(GenericArray::from_slice(&ikm));
        let prk = s2v(&mut mac, &[info], salt.unwrap_or(&[0u8; 16]));

        Kdf {
            ctr: C::new(&prk),
            finished: false
        }
    }
}

impl<C: Ctr> XofReader for Kdf<C> {
    fn read(&mut self, buffer: &mut [u8]) {
        if self.finished {
            // TODO: support multiple read invocations
            panic!("already finished!");
        }

        buffer.clear();
        self.ctr.xor_in_place(&[0u8; IV_SIZE], buffer);
        self.finished = true;
    }
}
