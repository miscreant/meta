//! `siv.rs`: The SIV misuse resistant block cipher mode of operation

use aes::{Aes128, Aes256};
use aes::block_cipher_trait::BlockCipher;
use aes::block_cipher_trait::generic_array::ArrayLength;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::generic_array::typenum::{U16, Unsigned};
use cmac::Cmac;
use core::marker::PhantomData;
use crypto_mac::Mac;
use ctr::{Aes128Ctr, Aes256Ctr, Ctr, IV_SIZE};
use error::Error;
use pmac::Pmac;
use s2v::s2v;
use subtle;

/// The SIV misuse resistant block cipher mode of operation
pub struct Siv<B, C, M>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    C: Ctr<B>,
    M: Mac,
{
    block_cipher: PhantomData<B>,
    mac: M,
    ctr: C,
}

/// AES-CMAC-SIV with a 128-bit key
pub type Aes128Siv = Siv<Aes128, Aes128Ctr, Cmac<Aes128>>;

/// AES-CMAC-SIV with a 256-bit key
pub type Aes256Siv = Siv<Aes256, Aes256Ctr, Cmac<Aes256>>;

/// AES-PMAC-SIV with a 128-bit key
pub type Aes128PmacSiv = Siv<Aes128, Aes128Ctr, Pmac<Aes128>>;

/// AES-PMAC-SIV with a 256-bit key
pub type Aes256PmacSiv = Siv<Aes256, Aes256Ctr, Pmac<Aes256>>;

impl<B, C, M> Siv<B, C, M>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    C: Ctr<B>,
    M: Mac<OutputSize = U16>,
{
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
            block_cipher: PhantomData,
            mac: M::new(GenericArray::from_slice(&key[..(key_size / 2)])),
            ctr: C::new(&key[(key_size / 2)..]),
        }
    }

    /// Encrypt the given plaintext in-place, replacing it with the SIV tag and
    /// ciphertext. Requires a buffer with 16-bytes additional space.
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
    /// Panics if `associated_data.len()` is greater than `MAX_ASSOCIATED_DATA`.
    pub fn seal_in_place<I, T>(&mut self, associated_data: I, plaintext: &mut [u8])
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        if plaintext.len() < IV_SIZE {
            panic!("plaintext buffer too small to hold MAC tag!");
        }

        // Compute the synthetic IV for this plaintext
        let iv = s2v(&mut self.mac, associated_data, &plaintext[IV_SIZE..]);
        plaintext[..IV_SIZE].copy_from_slice(iv.as_slice());
        self.ctr
            .xor_in_place(&zero_iv_bits(&iv), &mut plaintext[IV_SIZE..]);
    }

    /// Decrypt the given ciphertext in-place, authenticating it against the
    /// synthetic IV included in the message.
    ///
    /// Returns a slice containing a decrypted message on success.
    pub fn open_in_place<'a, I, T>(
        &mut self,
        associated_data: I,
        ciphertext: &'a mut [u8],
    ) -> Result<&'a [u8], Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        if ciphertext.len() < IV_SIZE {
            return Err(Error);
        }

        let iv = zero_iv_bits(&ciphertext[..IV_SIZE]);
        self.ctr.xor_in_place(&iv, &mut ciphertext[IV_SIZE..]);

        let actual_tag = s2v(&mut self.mac, associated_data, &ciphertext[IV_SIZE..]);
        if subtle::slices_equal(actual_tag.as_slice(), &ciphertext[..IV_SIZE]) != 1 {
            // Re-encrypt the decrypted plaintext to avoid revealing it
            self.ctr.xor_in_place(&iv, &mut ciphertext[IV_SIZE..]);
            return Err(Error);
        }

        Ok(&ciphertext[IV_SIZE..])
    }

    /// Encrypt the given plaintext, allocating and returning a Vec<u8> for the ciphertext
    #[cfg(feature = "std")]
    pub fn seal<I, T>(&mut self, associated_data: I, plaintext: &[u8]) -> Vec<u8>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut buffer = vec![0; IV_SIZE + plaintext.len()];
        buffer[IV_SIZE..].copy_from_slice(plaintext);
        self.seal_in_place(associated_data, &mut buffer);
        buffer
    }

    /// Decrypt the given ciphertext, allocating and returning a Vec<u8> for the plaintext
    #[cfg(feature = "std")]
    pub fn open<I, T>(&mut self, associated_data: I, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut buffer = Vec::from(ciphertext);
        self.open_in_place(associated_data, &mut buffer)?;
        buffer.drain(..IV_SIZE);
        Ok(buffer)
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
