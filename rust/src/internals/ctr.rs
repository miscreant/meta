//! `internals/ctr.rs`: Counter Mode encryption/decryption

use super::{Block, Block8, BlockCipher, BLOCK_SIZE};
use byteorder::{BigEndian, ByteOrder};
use clear_on_drop::clear::Clear;

/// Counter Mode encryption/decryption
pub struct Ctr<C: BlockCipher> {
    cipher: C,
    buffer: Block8,
    buffer_pos: usize,
}

impl<C: BlockCipher> Ctr<C> {
    /// Create a new CTR instance with the given cipher
    #[inline]
    pub fn new(cipher: C) -> Self {
        Self {
            cipher: cipher,
            buffer: Block8::new(),
            buffer_pos: 8 * BLOCK_SIZE,
        }
    }

    /// Reset the internal cipher state back to its initial values
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.buffer_pos = 8 * BLOCK_SIZE;
    }

    /// Encrypt/decrypt the given data in-place, updating the internal cipher state
    ///
    /// Accepts a mutable counter value, which is also updated in-place
    pub fn transform(&mut self, counter: &mut Block, data: &mut [u8]) {
        let mut ctr = BigEndian::read_u128(counter.as_ref());

        for b in data {
            self.fill_buffer(&mut ctr);
            *b ^= self.buffer.as_ref()[self.buffer_pos];
            self.buffer_pos = self.buffer_pos.checked_add(1).expect("overflow");
        }

        BigEndian::write_u128(counter.as_mut(), ctr);
    }

    /// Fill the internal buffer of AES-CTR values
    #[inline]
    fn fill_buffer(&mut self, counter: &mut u128) {
        if self.buffer_pos != 8 * BLOCK_SIZE {
            return;
        }

        for chunk in self.buffer.as_mut().chunks_mut(BLOCK_SIZE) {
            BigEndian::write_u128(chunk, *counter);

            // AES-CTR uses a wrapping counter
            *counter = counter.wrapping_add(1);
        }

        self.cipher.encrypt8(&mut self.buffer);
        self.buffer_pos = 0;
    }
}
