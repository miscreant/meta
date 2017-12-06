//! `stream.rs`: The STREAM online authenticated encryption construction.
//! See <https://eprint.iacr.org/2015/189.pdf> for definition.

use aead::{self, Aes128Siv, Aes128PmacSiv, Aes256Siv, Aes256PmacSiv};
use byteorder::{BigEndian, ByteOrder};

/// Size of a nonce required by STREAM in bytes
pub const NONCE_SIZE: usize = 8;

/// Byte flag indicating this is the last block in the STREAM (otherwise 0)
const LAST_BLOCK_FLAG: u8 = 1;

/// A STREAM encryptor with a 32-bit counter, generalized for any AEAD algorithm
///
/// This corresponds to the ℰ stream encryptor object as defined in the paper
/// Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance
pub struct Encryptor<A: aead::Algorithm> {
    alg: A,
    nonce: NonceEncoder32,
}

/// AES-CMAC-SIV STREAM encryptor with 256-bit key size (128-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes128SivEncryptor = Encryptor<Aes128Siv>;

/// AES-CMAC-SIV STREAM encryptor with 512-bit key size (256-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes256SivEncryptor = Encryptor<Aes256Siv>;

/// AES-PMAC-SIV STREAM encryptor with 256-bit key size (128-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes128PmacSivEncryptor = Encryptor<Aes128PmacSiv>;

/// AES-PMAC-SIV STREAM encryptor with 512-bit key size (256-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes256PmacSivEncryptor = Encryptor<Aes256PmacSiv>;

impl<A: aead::Algorithm> Encryptor<A> {
    /// Create a new STREAM encryptor, initialized with a given key and nonce.
    ///
    /// Panics if the key or nonce is the wrong size.
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        Self {
            alg: A::new(key),
            nonce: NonceEncoder32::new(nonce),
        }
    }

    /// Encrypt the next message in the stream in-place
    pub fn seal_next_in_place(&mut self, ad: &[u8], buffer: &mut [u8]) {
        self.alg.seal_in_place(self.nonce.as_slice(), ad, buffer);
        self.nonce.increment();
    }

    /// Encrypt the final message in-place, consuming the stream encryptor
    pub fn seal_last_in_place(mut self, ad: &[u8], buffer: &mut [u8]) {
        self.alg.seal_in_place(&self.nonce.finish(), ad, buffer);
    }
}

/// A STREAM decryptor with a 32-bit counter, generalized for any AEAD algorithm
///
/// This corresponds to the 𝒟 stream decryptor object as defined in the paper
/// Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance
pub struct Decryptor<A: aead::Algorithm> {
    alg: A,
    nonce: NonceEncoder32,
}

/// AES-CMAC-SIV STREAM decryptor with 256-bit key size (128-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes128SivDecryptor = Decryptor<Aes128Siv>;

/// AES-CMAC-SIV STREAM decryptor with 512-bit key size (256-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes256SivDecryptor = Decryptor<Aes256Siv>;

/// AES-PMAC-SIV STREAM decryptor with 256-bit key size (128-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes128PmacSivDecryptor = Decryptor<Aes128PmacSiv>;

/// AES-PMAC-SIV STREAM decryptor with 512-bit key size (256-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes256PmacSivDecryptor = Decryptor<Aes256PmacSiv>;

impl<A: aead::Algorithm> Decryptor<A> {
    /// Create a new STREAM decryptor, initialized with a given key and nonce.
    ///
    /// Panics if the key or nonce is the wrong size.
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        Self {
            alg: A::new(key),
            nonce: NonceEncoder32::new(nonce),
        }
    }

    /// Decrypt the next message in the stream in-place
    pub fn open_next_in_place<'a>(
        &mut self,
        ad: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], ()> {
        let result = self.alg.open_in_place(self.nonce.as_slice(), ad, buffer)?;
        self.nonce.increment();
        Ok(result)
    }

    /// Decrypt the final message in-place, consuming the stream decryptor
    pub fn open_last_in_place<'a>(
        mut self,
        ad: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], ()> {
        self.alg.open_in_place(&self.nonce.finish(), ad, buffer)
    }
}

/// STREAM nonce including space for 32-bit counter and 1-byte last block flag
type StreamNonce = [u8; NONCE_SIZE + 4 + 1];

/// Computes STREAM nonces based on the current position in the STREAM.
///
/// Accepts a 64-bit nonce and uses a 32-bit counter internally.
///
/// Panics if the nonce size is incorrect, 32-bit counter overflows
struct NonceEncoder32 {
    value: StreamNonce,
    counter: u32,
}

impl NonceEncoder32 {
    /// Create a new nonce encoder object
    fn new(prefix: &[u8]) -> Self {
        if prefix.len() != NONCE_SIZE {
            panic!(
                "incorrect nonce size (expected {}, got {})",
                NONCE_SIZE,
                prefix.len()
            );
        }

        let mut result = Self {
            value: Default::default(),
            counter: 0,
        };

        result.value[..NONCE_SIZE].copy_from_slice(prefix);
        result
    }

    /// Increment the nonce value in-place
    pub fn increment(&mut self) {
        self.counter = self.counter.checked_add(1).expect(
            "STREAM nonce counter overflowed",
        );

        BigEndian::write_u32(&mut self.value[NONCE_SIZE..(NONCE_SIZE + 4)], self.counter);
    }

    /// Borrow the current value as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.value
    }

    /// Compute the final nonce value, consuming self and returning the final
    /// nonce value.
    pub fn finish(mut self) -> StreamNonce {
        *self.value.iter_mut().last().unwrap() = LAST_BLOCK_FLAG;
        self.value
    }
}
