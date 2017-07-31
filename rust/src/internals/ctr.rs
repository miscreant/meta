//! `internals/ctr.rs`: Counter Mode encryption/decryption

use super::{BLOCK_SIZE, Block, BlockCipher};
use super::util;

/// Counter Mode encryption/decryption
pub struct Ctr<C: BlockCipher> {
    cipher: C,
    buffer: Block,
    buffer_pos: usize,
}

impl<C: BlockCipher> Ctr<C> {
    /// Create a new CTR instance with the given cipher
    #[inline]
    pub fn new(cipher: C) -> Self {
        Self {
            cipher: cipher,
            buffer: Block::new(),
            buffer_pos: BLOCK_SIZE,
        }
    }

    /// Reset the internal cipher state back to its initial values
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.buffer_pos = BLOCK_SIZE;
    }

    /// Encrypt/decrypt the given data in-place, updating the internal cipher state
    ///
    /// Accepts a mutable counter value, which is also updated in-place
    pub fn transform(&mut self, counter: &mut Block, data: &mut [u8]) {
        for b in data {
            if self.buffer_pos == BLOCK_SIZE {
                self.buffer.copy_from_block(counter);
                self.cipher.encrypt(&mut self.buffer);
                self.buffer_pos = 0;
                util::ctr_increment(counter.as_mut());
            }

            *b ^= self.buffer.as_ref()[self.buffer_pos];
            self.buffer_pos = self.buffer_pos.checked_add(1).expect("overflow");
        }
    }
}
