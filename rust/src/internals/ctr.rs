//! `internals/ctr.rs`: Counter Mode encryption/decryption

use super::{BLOCK_SIZE, Block, Block8, BlockCipher, xor};
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
    pub fn transform(&mut self, counter: &mut Block, msg: &mut [u8]) {
        let mut ctr = BigEndian::read_u128(counter.as_ref());

        let mut msg_pos: usize = 0;
        let mut msg_len: usize = msg.len();
        let remaining: usize = 8 * BLOCK_SIZE - self.buffer_pos;

        if msg_len > remaining {
            xor::in_place(
                &mut msg[..remaining],
                &self.buffer.as_ref()[self.buffer_pos..],
            );

            msg_pos = msg_pos.checked_add(remaining).expect("overflow");
            msg_len = msg_len.checked_sub(remaining).expect("underflow");

            self.fill_buffer(&mut ctr);
        }

        while msg_len > 8 * BLOCK_SIZE {
            xor::in_place(
                array_mut_ref!(msg, msg_pos, 8 * BLOCK_SIZE),
                self.buffer.as_ref(),
            );

            msg_pos = msg_pos.checked_add(8 * BLOCK_SIZE).expect("overflow");
            msg_len = msg_len.checked_sub(8 * BLOCK_SIZE).expect("underflow");

            self.fill_buffer(&mut ctr);
        }

        if msg_len > 0 {
            let buf_end = self.buffer_pos.checked_add(msg_len).expect("overflow");

            xor::in_place(
                &mut msg[msg_pos..],
                &self.buffer.as_ref()[self.buffer_pos..buf_end],
            );

            self.buffer_pos = self.buffer_pos.checked_add(msg_len).expect("overflow");
        }

        BigEndian::write_u128(counter.as_mut(), ctr);
    }

    /// Fill the internal buffer of AES-CTR values
    #[inline]
    fn fill_buffer(&mut self, counter: &mut u128) {
        for chunk in self.buffer.as_mut().chunks_mut(BLOCK_SIZE) {
            BigEndian::write_u128(chunk, *counter);

            // AES-CTR uses a wrapping counter
            *counter = counter.wrapping_add(1);
        }

        self.cipher.encrypt8(&mut self.buffer);
        self.buffer_pos = 0;
    }
}
