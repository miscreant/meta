//! `internals/ctr.rs`: Counter Mode encryption/decryption

use super::{Block, BlockCipher, BLOCK_SIZE};
use byteorder::{BigEndian, ByteOrder};

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
                increment_ctr(counter);
            }

            *b ^= self.buffer.as_ref()[self.buffer_pos];
            self.buffer_pos = self.buffer_pos.checked_add(1).expect("overflow");
        }
    }
}

/// Increment a CTR-mode counter. Panics on overflow
// TODO: use verified asm implementation?
fn increment_ctr(block: &mut Block) {
    let counter = BigEndian::read_u128(block.as_ref());
    BigEndian::write_u128(block.as_mut(), counter.wrapping_add(1));
}

#[cfg(test)]
mod tests {
    use super::{Block, BLOCK_SIZE};
    use super::increment_ctr;

    #[test]
    fn counter_increment() {
        let mut block = Block::new();
        increment_ctr(&mut block);
        assert_eq!(block.as_ref(), *b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01");
    }

    #[test]
    fn counter_overflow() {
        let mut block = Block::from([0xFFu8; BLOCK_SIZE]);
        increment_ctr(&mut block);
        assert_eq!(block.as_ref(), &[0u8; BLOCK_SIZE]);
    }
}
