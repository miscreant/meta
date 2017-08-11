//! `internals/cmac.rs`: Cipher-based Message Authentication Code

use super::{BLOCK_SIZE, Block, BlockCipher, Mac, xor};
use clear_on_drop::clear::Clear;

type Tag = Block;

/// Cipher-based Message Authentication Code
pub struct Cmac<C: BlockCipher> {
    cipher: C,
    subkey1: Block,
    subkey2: Block,
    buffer: Block,
    buffer_pos: usize,
    finished: bool,
}

impl<C: BlockCipher> Mac<C> for Cmac<C> {
    /// Create a new CMAC instance with the given cipher
    #[inline]
    fn new(cipher: C) -> Self {
        let mut subkey1 = Block::new();
        cipher.encrypt(&mut subkey1);
        subkey1.dbl();

        let mut subkey2 = subkey1.clone();
        subkey2.dbl();

        Self {
            subkey1: subkey1,
            subkey2: subkey2,
            buffer: Block::new(),
            cipher: cipher,
            buffer_pos: 0,
            finished: false,
        }
    }

    /// Reset a CMAC instance back to its initial buffer
    #[inline]
    fn reset(&mut self) {
        self.buffer.clear();
        self.buffer_pos = 0;
        self.finished = false;
    }

    /// Update the CMAC buffer with the given message
    ///
    /// Panics if we're already in a finished buffer (must reset before reusing)
    fn update(&mut self, msg: &[u8]) {
        if self.finished {
            panic!("already finished");
        }

        let mut msg_pos: usize = 0;
        let mut msg_len: usize = msg.len();
        let remaining = BLOCK_SIZE - self.buffer_pos;

        if msg_len > remaining {
            xor::in_place(
                &mut self.buffer.as_mut()[self.buffer_pos..],
                &msg[..remaining],
            );

            msg_len = msg_len.checked_sub(remaining).expect("underflow");
            msg_pos = msg_pos.checked_add(remaining).expect("overflow");

            self.cipher.encrypt(&mut self.buffer);
            self.buffer_pos = 0;
        }

        while msg_len > BLOCK_SIZE {
            self.buffer.xor_in_place(
                array_ref!(msg, msg_pos, BLOCK_SIZE),
            );

            msg_len = msg_len.checked_sub(BLOCK_SIZE).expect("underflow");
            msg_pos = msg_pos.checked_add(BLOCK_SIZE).expect("overflow");

            self.cipher.encrypt(&mut self.buffer);
        }

        if msg_len > 0 {
            let buffer_end = self.buffer_pos.checked_add(msg_len).expect("overflow");

            xor::in_place(
                &mut self.buffer.as_mut()[self.buffer_pos..buffer_end],
                &msg[msg_pos..msg_pos.checked_add(msg_len).expect("overflow")],
            );

            self.buffer_pos = self.buffer_pos.checked_add(msg_len).expect("overflow");
        }
    }

    /// Finish computing CMAC, returning the computed tag
    ///
    /// Panics if we're already in a finished buffer (must reset before reusing)
    fn finish(&mut self) -> Tag {
        if self.finished {
            panic!("already finished");
        }

        if self.buffer_pos == BLOCK_SIZE {
            self.buffer.xor_in_place(&self.subkey1);
        } else {
            self.buffer.xor_in_place(&self.subkey2);
            self.buffer.as_mut()[self.buffer_pos] ^= 0x80;
        }

        self.cipher.encrypt(&mut self.buffer);
        self.finished = true;

        self.buffer.clone()
    }
}
