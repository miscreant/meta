//! `stream.rs`: The STREAM online authenticated encryption construction.
//! See <https://eprint.iacr.org/2015/189.pdf> for definition.

use aead::{self, Aes128Siv, Aes128PmacSiv, Aes256Siv, Aes256PmacSiv};
use byteorder::{BigEndian, ByteOrder};
use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::U13;

/// Byte flag indicating this is the last block in the STREAM (otherwise 0)
const LAST_BLOCK_FLAG: u8 = 1;

/// A STREAM encryptor with a 32-bit counter, generalized for any AEAD algorithm
///
/// This corresponds to the ℰ stream encryptor object as defined in the paper
/// Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance
pub struct Encryptor<A: aead::Algorithm, N: ArrayLength<u8>> {
    alg: A,
    nonce: NonceEncoder32<N>,
}

/// AES-CMAC-SIV STREAM encryptor with 256-bit key size (128-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes128SivEncryptor = Encryptor<Aes128Siv, U13>;

/// AES-CMAC-SIV STREAM encryptor with 512-bit key size (256-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes256SivEncryptor = Encryptor<Aes256Siv, U13>;

/// AES-PMAC-SIV STREAM encryptor with 256-bit key size (128-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes128PmacSivEncryptor = Encryptor<Aes128PmacSiv, U13>;

/// AES-PMAC-SIV STREAM encryptor with 512-bit key size (256-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes256PmacSivEncryptor = Encryptor<Aes256PmacSiv, U13>;

impl<A, N> Encryptor<A, N>
where
    A: aead::Algorithm,
    N: ArrayLength<u8>,
{
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
pub struct Decryptor<A: aead::Algorithm, N: ArrayLength<u8>> {
    alg: A,
    nonce: NonceEncoder32<N>,
}

/// AES-CMAC-SIV STREAM decryptor with 256-bit key size (128-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes128SivDecryptor = Decryptor<Aes128Siv, U13>;

/// AES-CMAC-SIV STREAM decryptor with 512-bit key size (256-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes256SivDecryptor = Decryptor<Aes256Siv, U13>;

/// AES-PMAC-SIV STREAM decryptor with 256-bit key size (128-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes128PmacSivDecryptor = Decryptor<Aes128PmacSiv, U13>;

/// AES-PMAC-SIV STREAM decryptor with 512-bit key size (256-bit security)
/// and a 64-bit (8-byte) nonce.
pub type Aes256PmacSivDecryptor = Decryptor<Aes256PmacSiv, U13>;

impl<A, N> Decryptor<A, N>
where
    A: aead::Algorithm,
    N: ArrayLength<u8>,
{
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

/// Computes STREAM nonces based on the current position in the stream (32-bit counter)
struct NonceEncoder32<N: ArrayLength<u8>> {
    value: GenericArray<u8, N>,
    counter: u32,
}

impl<N: ArrayLength<u8>> NonceEncoder32<N> {
    /// Create a new nonce encoder object
    fn new(prefix: &[u8]) -> Self {
        if prefix.len() != Self::prefix_length() {
            panic!(
                "incorrect nonce size (expected {}, got {})",
                Self::prefix_length(),
                prefix.len()
            );
        }

        let mut result = Self {
            value: Default::default(),
            counter: 0,
        };

        result.value[..Self::prefix_length()].copy_from_slice(prefix);
        result
    }

    /// Increment the nonce value in-place
    pub fn increment(&mut self) {
        self.counter = self.counter.checked_add(1).expect(
            "STREAM nonce counter overflowed",
        );

        BigEndian::write_u32(
            &mut self.value[Self::prefix_length()..(Self::prefix_length() + 4)],
            self.counter,
        );
    }

    /// Borrow the current value as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.value
    }

    /// Compute the final nonce value, consuming self and returning the final
    /// nonce value.
    pub fn finish(mut self) -> GenericArray<u8, N> {
        *self.value.iter_mut().last().unwrap() = LAST_BLOCK_FLAG;
        self.value
    }

    /// Expected prefix length for this buffer size
    #[inline]
    fn prefix_length() -> usize {
        N::to_usize().checked_sub(5).expect(
            "buffer less than 5-bytes",
        )
    }
}
