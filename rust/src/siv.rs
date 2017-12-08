//! `siv.rs`: The SIV misuse resistant block cipher mode of operation

use aesni::{Aes128, Aes256};
use buffer::Buffer;
use cmac::Cmac;
use crypto_mac::Mac;
use ctr::{Aes128Ctr, Aes256Ctr, Ctr, IV_SIZE};
use error::Error;
use generic_array::GenericArray;
use generic_array::typenum::{U16, Unsigned};
use pmac::Pmac;
use s2v::s2v;
use subtle;

/// The SIV misuse resistant block cipher mode of operation
pub struct Siv<C: Ctr, M: Mac> {
    mac: M,
    ctr: C,
}

/// AES-CMAC-SIV with a 128-bit key
pub type Aes128Siv = Siv<Aes128Ctr, Cmac<Aes128>>;

/// AES-CMAC-SIV with a 256-bit key
pub type Aes256Siv = Siv<Aes256Ctr, Cmac<Aes256>>;

/// AES-PMAC-SIV with a 128-bit key
pub type Aes128PmacSiv = Siv<Aes128Ctr, Pmac<Aes128>>;

/// AES-PMAC-SIV with a 256-bit key
pub type Aes256PmacSiv = Siv<Aes256Ctr, Pmac<Aes256>>;

impl<C: Ctr, M: Mac<OutputSize = U16>> Siv<C, M> {
    /// Create a new AES-SIV instance
    ///
    /// Panics if the key is the wrong length
    pub fn new(key: &[u8]) -> Self {
        let key_size = M::KeySize::to_usize() * 2;

        assert_eq!(
            key.len(),
            key_size,
            "expected {}-byte key, got {}",
            key_size,
            key.len()
        );

        Self {
            mac: M::new(GenericArray::from_slice(&key[..(key_size / 2)])),
            ctr: C::new(&key[(key_size / 2)..]),
        }
    }

    /// Encrypt the given plaintext in-place, replacing it with the SIV tag and
    /// ciphertext. Requires a buffer with 16-bytes additional space.
    ///
    /// # Usage
    ///
    /// The `miscreant::Buffer` type is intended to simplify slicing the buffer
    /// into respective "message" and "tag" slices.
    ///
    /// The buffer must include an additional 16-bytes of space in which to
    /// write the SIV tag (at the beginning of the buffer).
    /// It's important to note that with AES-SIV the "tag" portion of the
    /// buffer lies at the beginning, and the "message" portion at the end.
    ///
    /// ```rust
    /// let buffer = [0u8; 21];
    /// let plaintext = &buffer[..buffer.len() - 16];
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `associated_data.len()` is greater than `MAX_ASSOCIATED_DATA`.
    pub fn seal_in_place<B, I, T>(&mut self, associated_data: I, buf: &mut Buffer<B>)
    where
        B: AsRef<[u8]> + AsMut<[u8]>,
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        // Compute the synthetic IV for this plaintext
        let siv = s2v(&mut self.mac, associated_data, buf.msg_slice());
        buf.mut_tag_slice().copy_from_slice(siv.as_slice());
        self.ctr.xor_in_place(
            &zero_iv_bits(&siv),
            buf.mut_msg_slice(),
        );
    }

    /// Decrypt the given ciphertext in-place, authenticating it against the
    /// synthetic IV included in the message.
    ///
    /// Returns a slice containing a decrypted message on success.
    pub fn open_in_place<B, I, T>(
        &mut self,
        associated_data: I,
        buf: &mut Buffer<B>,
    ) -> Result<(), Error>
    where
        B: AsRef<[u8]> + AsMut<[u8]>,
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let iv = zero_iv_bits(buf.tag_slice());
        self.ctr.xor_in_place(&iv, buf.mut_msg_slice());

        let computed_tag = s2v(&mut self.mac, associated_data, buf.msg_slice());
        if subtle::slices_equal(computed_tag.as_slice(), buf.tag_slice()) != 1 {
            // On verify fail, re-encrypt the unauthenticated plaintext to avoid revealing it
            self.ctr.xor_in_place(&iv, buf.mut_msg_slice());
            return Err(Error);
        }

        Ok(())
    }

    /// Encrypt the given plaintext, allocating and returning a Vec<u8> for the ciphertext
    #[cfg(feature = "std")]
    pub fn seal<I, T>(&mut self, associated_data: I, plaintext: &[u8]) -> Vec<u8>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut buf = Buffer::from_plaintext(plaintext);
        self.seal_in_place(associated_data, &mut buf);
        buf.into_contents()
    }

    /// Decrypt the given ciphertext, allocating and returning a Vec<u8> for the plaintext
    #[cfg(feature = "std")]
    pub fn open<I, T>(&mut self, associated_data: I, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut buf = Buffer::from(Vec::from(ciphertext));
        self.open_in_place(associated_data, &mut buf)?;
        Ok(buf.into_plaintext())
    }
}

/// Zero out the top bits in the last 32-bit words of the IV
#[inline]
fn zero_iv_bits(iv: &[u8]) -> [u8; IV_SIZE] {
    debug_assert_eq!(iv.len(), IV_SIZE, "wrong IV size: {}", iv.len());

    let mut result = [0u8; IV_SIZE];
    result.copy_from_slice(iv);

    // "We zero-out the top bit in each of the last two 32-bit words
    // of the IV before assigning it to Ctr"
    //  — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
    result[8] &= 0x7f;
    result[12] &= 0x7f;

    result
}
