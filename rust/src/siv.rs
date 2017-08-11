//! `siv.rs`: The SIV misuse resistant block cipher mode of operation

use internals::{Aes128, Aes256};
use internals::{BLOCK_SIZE, Block, BlockCipher, Cmac, Ctr, Mac};
use subtle::Equal;

/// Maximum number of associated data items
pub const MAX_ASSOCIATED_DATA: usize = 126;

/// A block of all zeroes
const ZERO_BLOCK: &[u8; BLOCK_SIZE] = &[0u8; BLOCK_SIZE];

/// A SIV tag
type Tag = Block;

/// The SIV misuse resistant block cipher mode of operation
pub struct Siv<C: BlockCipher, M: Mac<C>> {
    mac: M,
    ctr: Ctr<C>,
}

/// AES-CMAC-SIV with a 128-bit key
pub type Aes128Siv = Siv<Aes128, Cmac<Aes128>>;

impl Aes128Siv {
    /// Create a new AES-SIV instance with a 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            mac: Cmac::new(Aes128::new(array_ref!(key, 0, 16))),
            ctr: Ctr::new(Aes128::new(array_ref!(key, 16, 16))),
        }
    }
}

/// AES-CMAC-SIV with a 256-bit key
pub type Aes256Siv = Siv<Aes256, Cmac<Aes256>>;

impl Aes256Siv {
    /// Create a new AES-SIV instance with a 64-byte key
    pub fn new(key: &[u8; 64]) -> Self {
        Self {
            mac: Cmac::new(Aes256::new(array_ref!(key, 0, 32))),
            ctr: Ctr::new(Aes256::new(array_ref!(key, 32, 32))),
        }
    }
}

impl<C: BlockCipher, M: Mac<C>> Siv<C, M> {
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
    /// Panics if `plaintext.len()` is less than `BLOCK_SIZE`.
    /// Panics if `associated_data.len()` is greater than `MAX_ASSOCIATED_DATA`.
    pub fn seal_in_place<I, T>(&mut self, associated_data: I, plaintext: &mut [u8])
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        if plaintext.len() < BLOCK_SIZE {
            panic!("plaintext buffer too small to hold SIV tag!");
        }

        // Compute the synthetic IV for this plaintext
        let mut iv = self.s2v(associated_data, &plaintext[BLOCK_SIZE..]);
        plaintext[..BLOCK_SIZE].copy_from_slice(iv.as_ref());

        zero_iv_bits(&mut iv);
        self.ctr.transform(&mut iv, &mut plaintext[BLOCK_SIZE..]);
        self.ctr.reset();
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
        if ciphertext.len() < BLOCK_SIZE {
            return Err(());
        }

        let mut iv = Block::from(&ciphertext[..BLOCK_SIZE]);
        zero_iv_bits(&mut iv);

        self.ctr.transform(&mut iv, &mut ciphertext[BLOCK_SIZE..]);
        self.ctr.reset();

        let actual_tag = self.s2v(associated_data, &ciphertext[BLOCK_SIZE..]);

        if actual_tag.ct_eq(&Block::from(&ciphertext[..BLOCK_SIZE])) != 1 {
            let mut iv = Block::from(&ciphertext[..BLOCK_SIZE]);

            // Re-encrypt the decrypted plaintext to avoid revealing it
            self.ctr.transform(&mut iv, &mut ciphertext[BLOCK_SIZE..]);
            self.ctr.reset();

            return Err(());
        }

        Ok(&ciphertext[BLOCK_SIZE..])
    }

    /// The S2V operation consists of the doubling and XORing of the outputs
    /// of the pseudo-random function CMAC.
    ///
    /// See Section 2.4 of RFC 5297 for more information
    fn s2v<I, T>(&mut self, associated_data: I, plaintext: &[u8]) -> Tag
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.mac.reset();
        self.mac.update(ZERO_BLOCK);
        let mut state = self.mac.finish();

        for (i, ad) in associated_data.into_iter().enumerate() {
            if i >= MAX_ASSOCIATED_DATA {
                panic!("too many associated data items!");
            }

            self.mac.reset();
            self.mac.update(ad.as_ref());

            state.dbl();
            state.xor_in_place(&self.mac.finish());
        }

        self.mac.reset();

        if plaintext.len() >= BLOCK_SIZE {
            let n = plaintext.len().checked_sub(BLOCK_SIZE).unwrap();
            self.mac.update(&plaintext[..n]);
            state.xor_in_place(array_ref!(plaintext, n, BLOCK_SIZE));
        } else {
            let mut tmp = Block::from(plaintext);
            tmp.as_mut()[plaintext.len()] = 0x80;

            state.dbl();
            state.xor_in_place(&tmp);
        };

        self.mac.update(state.as_ref());
        let result = self.mac.finish();
        self.mac.reset();

        result
    }
}

/// Zero out the top bits in the last 32-bit words of the IV
fn zero_iv_bits(block: &mut Block) {
    // "We zero-out the top bit in each of the last two 32-bit words
    // of the IV before assigning it to Ctr"
    //  — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
    block.as_mut()[8] &= 0x7f;
    block.as_mut()[12] &= 0x7f;
}
