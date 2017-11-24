//! `siv.rs`: The SIV misuse resistant block cipher mode of operation

use aesni::{Aes128, Aes256};
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::U16;
use cmac::Cmac;
use crypto_mac::Mac;
use ctr::{Aes128Ctr, Aes256Ctr, Ctr, Iv, IV_SIZE};
use dbl::Dbl;
use pmac::Pmac;
use subtle;

/// Maximum number of associated data items
pub const MAX_ASSOCIATED_DATA: usize = 126;

/// The SIV misuse resistant block cipher mode of operation
pub struct Siv<C: Ctr, M: Mac> {
    mac: M,
    ctr: C,
}

/// AES-CMAC-SIV with a 128-bit key
pub type Aes128Siv = Siv<Aes128Ctr, Cmac<Aes128>>;

impl Aes128Siv {
    /// Create a new AES-SIV instance with a 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            mac: Cmac::new(GenericArray::from_slice(&key[..16])),
            ctr: Aes128Ctr::new(array_ref!(key, 16, 16)),
        }
    }
}

/// AES-CMAC-SIV with a 256-bit key
pub type Aes256Siv = Siv<Aes256Ctr, Cmac<Aes256>>;

impl Aes256Siv {
    /// Create a new AES-SIV instance with a 64-byte key
    pub fn new(key: &[u8; 64]) -> Self {
        Self {
            mac: Cmac::new(GenericArray::from_slice(&key[..32])),
            ctr: Aes256Ctr::new(array_ref!(key, 32, 32)),
        }
    }
}

/// AES-PMAC-SIV with a 128-bit key
pub type Aes128PmacSiv = Siv<Aes128Ctr, Pmac<Aes128>>;

impl Aes128PmacSiv {
    /// Create a new AES-SIV instance with a 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            mac: Pmac::new(GenericArray::from_slice(&key[..16])),
            ctr: Aes128Ctr::new(array_ref!(key, 16, 16)),
        }
    }
}

/// AES-SIV with a 256-bit key
pub type Aes256PmacSiv = Siv<Aes256Ctr, Pmac<Aes256>>;

impl Aes256PmacSiv {
    /// Create a new AES-SIV instance with a 64-byte key
    pub fn new(key: &[u8; 64]) -> Self {
        Self {
            mac: Pmac::new(GenericArray::from_slice(&key[..32])),
            ctr: Aes256Ctr::new(array_ref!(key, 32, 32)),
        }
    }
}

impl<C: Ctr, M: Mac<OutputSize = U16>> Siv<C, M> {
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
    /// Panics if `plaintext.len()` is less than `IV_SIZE`.
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
        let mut iv = self.s2v(associated_data, &plaintext[IV_SIZE..]);
        plaintext[..IV_SIZE].copy_from_slice(&iv);

        zero_iv_bits(&mut iv);
        self.ctr.xor_in_place(&iv, &mut plaintext[IV_SIZE..]);
    }

    /// Decrypt the given ciphertext in-place, authenticating it against the
    /// synthetic IV included in the message.
    ///
    /// Returns a slice containing a decrypted message on success.
    pub fn open_in_place<'a, I, T>(
        &mut self,
        associated_data: I,
        ciphertext: &'a mut [u8],
    ) -> Result<&'a [u8], ()>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        if ciphertext.len() < IV_SIZE {
            return Err(());
        }

        let mut iv = Iv::clone_from_slice(&ciphertext[..IV_SIZE]);
        zero_iv_bits(&mut iv);
        self.ctr.xor_in_place(&iv, &mut ciphertext[IV_SIZE..]);

        let actual_tag = self.s2v(associated_data, &ciphertext[IV_SIZE..]);
        if subtle::slices_equal(actual_tag.as_slice(), &ciphertext[..IV_SIZE]) != 1 {
            // Re-encrypt the decrypted plaintext to avoid revealing it
            self.ctr.xor_in_place(&iv, &mut ciphertext[IV_SIZE..]);
            return Err(());
        }

        Ok(&ciphertext[IV_SIZE..])
    }

    /// The S2V operation consists of the doubling and XORing of the outputs
    /// of a pseudo-random function (CMAC or PMAC).
    ///
    /// See Section 2.4 of RFC 5297 for more information
    fn s2v<I, T>(&mut self, associated_data: I, plaintext: &[u8]) -> Iv
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.mac.input(&[0u8; IV_SIZE]);
        let mut state = self.mac.result().code();

        for (i, ad) in associated_data.into_iter().enumerate() {
            if i >= MAX_ASSOCIATED_DATA {
                panic!("too many associated data items!");
            }

            state = state.dbl();
            self.mac.input(ad.as_ref());
            let code = self.mac.result().code();
            xor_in_place(&mut state, &code);
        }

        if plaintext.len() >= IV_SIZE {
            let n = plaintext.len().checked_sub(IV_SIZE).unwrap();
            self.mac.input(&plaintext[..n]);
            xor_in_place(&mut state, &plaintext[n..]);
        } else {
            state = state.dbl();
            xor_in_place(&mut state, plaintext);
            state[plaintext.len()] ^= 0x80;
        };

        self.mac.input(state.as_ref());
        self.mac.result().code()
    }
}

/// XOR the second argument into the first in-place. Slices do not have to be
/// aligned in memory.
///
/// Panics if the two slices aren't the same length
#[inline]
fn xor_in_place(a: &mut [u8], b: &[u8]) {
    for i in 0..b.len() {
        a[i] ^= b[i];
    }
}

/// Zero out the top bits in the last 32-bit words of the IV
#[inline]
fn zero_iv_bits(block: &mut Iv) {
    // "We zero-out the top bit in each of the last two 32-bit words
    // of the IV before assigning it to Ctr"
    //  — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
    block.as_mut()[8] &= 0x7f;
    block.as_mut()[12] &= 0x7f;
}
