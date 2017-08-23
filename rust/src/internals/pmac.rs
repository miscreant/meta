//! `internals/pmac.rs`: Parallel Message Authentication Code
//! Defined in http://web.cs.ucdavis.edu/~rogaway/ocb/pmac.pdf

use super::{BLOCK_SIZE, Block, Block8, BlockCipher, Mac, xor};
use super::block::R;
use byteorder::{BigEndian, ByteOrder};
use clear_on_drop::clear::Clear;

type Tag = Block;

// Number of L blocks to precompute (i.e. µ in the PMAC paper)
// TODO: dynamically compute these as needed
const PRECOMPUTED_BLOCKS: usize = 31;

/// Parallel Message Authentication Code
pub struct Pmac<C: BlockCipher> {
    // C is the block cipher we're using (i.e. AES-128 or AES-256)
    cipher: C,

    // L is defined as follows (quoted from the PMAC paper):
    //
    // Equation 1:
    //
    //     a · x =
    //         a<<1 if firstbit(a)=0
    //         (a<<1) ⊕ 0¹²⁰10000111 if firstbit(a)=1
    //
    // Equation 2:
    //
    //     a · x⁻¹ =
    //         a>>1 if lastbit(a)=0
    //         (a>>1) ⊕ 10¹²⁰1000011 if lastbit(a)=1
    //
    // Let L(0) ← L. For i ∈ [1..µ], compute L(i) ← L(i − 1) · x by
    // Equation (1) using a shift and a conditional xor.
    //
    // Compute L(−1) ← L · x⁻¹ by Equation (2), using a shift and a
    // conditional xor.
    //
    // Save the values L(−1), L(0), L(1), L(2), ..., L(µ) in a table.
    // (Alternatively, [ed: as we have done in this codebase] defer computing
    // some or  all of these L(i) values until the value is actually needed.)
    l: [Block; PRECOMPUTED_BLOCKS],

    // L(-1) is computed as described above, and is XORed into the tag in the
    // event the message length is a multiple of the block size
    l_inv: Block,

    // tag is the PMAC tag-in-progress
    tag: Tag,

    // offset is a block counter-specific tweak to the MAC value
    offset: Block,

    // buffer is input plaintext, which we process a block-at-a-time
    buffer: Block8,

    // buffer_pos marks the end of plaintext in the buffer
    buffer_pos: usize,

    // counter is the number of blocks we have MAC'd so far
    counter: usize,

    // finished is set true when we are done processing a message, and forbids
    // any subsequent writes until we reset the internal state
    finished: bool,
}

impl<C: BlockCipher> Mac<C> for Pmac<C> {
    /// Create a new PMAC instance with the given cipher
    #[inline]
    fn new(cipher: C) -> Self {
        let mut l: [Block; PRECOMPUTED_BLOCKS] = Default::default();
        let mut tmp = Block::new();

        cipher.encrypt(&mut tmp);

        for block in &mut l {
            block.copy_from_block(&tmp);
            tmp.dbl();
        }

        // Compute L(−1) ← L · x⁻¹:
        //
        // a>>1 if lastbit(a)=0
        // (a>>1) ⊕ 10¹²⁰1000011 if lastbit(a)=1
        //
        let mut l_inv = Block::new();
        let l_0 = BigEndian::read_u128(l[0].as_ref());
        let inv = (l_0 >> 1) ^ ((l_0 & 0x1) * (0x80 << 120 | R >> 1));
        BigEndian::write_u128(l_inv.as_mut(), inv);

        Self {
            cipher: cipher,
            l: l,
            l_inv: l_inv,
            tag: Tag::new(),
            offset: Block::new(),
            buffer: Block8::new(),
            buffer_pos: 0,
            counter: 0,
            finished: false,
        }
    }

    /// Reset a PMAC instance back to its initial state
    #[inline]
    fn reset(&mut self) {
        self.tag.clear();
        self.offset.clear();
        self.buffer.clear();
        self.buffer_pos = 0;
        self.counter = 0;
        self.finished = false;
    }

    /// Update the PMAC buffer with the given message
    ///
    /// Panics if we're already in a finished state (must reset before reusing)
    fn update(&mut self, msg: &[u8]) {
        assert_eq!(self.finished, false, "already finished");

        let mut msg_pos: usize = 0;
        let mut msg_len: usize = msg.len();
        let remaining: usize = 8 * BLOCK_SIZE - self.buffer_pos;

        // Finish filling the 8 * block internal buffer with the message
        if msg_len > remaining {
            self.buffer.as_mut()[self.buffer_pos..].copy_from_slice(&msg[..remaining]);

            msg_pos = msg_pos.checked_add(remaining).expect("overflow");
            msg_len = msg_len.checked_sub(remaining).expect("underflow");

            self.process_buffer();
        }

        // So long as we have more than 8 * blocks worth of data, compute
        // whole-sized blocks at a time.
        while msg_len > 8 * BLOCK_SIZE {
            self.buffer.as_mut().copy_from_slice(
                array_ref!(msg, msg_pos, 8 * BLOCK_SIZE),
            );

            msg_pos = msg_pos.checked_add(8 * BLOCK_SIZE).expect("overflow");
            msg_len = msg_len.checked_sub(8 * BLOCK_SIZE).expect("underflow");

            self.process_buffer();
        }

        if msg_len > 0 {
            let buf_end = self.buffer_pos.checked_add(msg_len).expect("overflow");

            self.buffer.as_mut()[self.buffer_pos..buf_end].copy_from_slice(&msg[msg_pos..]);

            self.buffer_pos = self.buffer_pos.checked_add(msg_len).expect("overflow");
        }
    }

    /// Finalize the MAC computation, returning the computed tag
    fn finish(&mut self) -> Tag {
        assert_eq!(self.finished, false, "already finished");

        let mut buf_pos = 0;
        let mut buf_len = self.buffer_pos;
        let mut block = Block::new();

        while buf_len > BLOCK_SIZE {
            self.offset.xor_in_place(
                self.l[(self.counter + 1).trailing_zeros() as usize].as_ref(),
            );
            self.counter = self.counter.checked_add(1).expect("overflow");

            block.copy_from_block(&self.offset);
            block.xor_in_place(array_ref!(self.buffer.as_mut(), buf_pos, BLOCK_SIZE));

            self.cipher.encrypt(&mut block);
            self.tag.xor_in_place(&block);

            buf_pos = buf_pos.checked_add(BLOCK_SIZE).expect("overflow");
            buf_len = buf_len.checked_sub(BLOCK_SIZE).expect("underflow");
        }

        if buf_len == BLOCK_SIZE {
            self.tag.xor_in_place(array_ref!(
                self.buffer.as_mut(),
                buf_pos,
                BLOCK_SIZE
            ));
            self.tag.xor_in_place(&self.l_inv);
        } else {
            let buf_end = buf_pos.checked_add(buf_len).expect("overflow");

            xor::in_place(
                &mut self.tag.as_mut()[..buf_len],
                &self.buffer.as_ref()[buf_pos..buf_end],
            );
            self.tag.as_mut()[buf_len] ^= 0x80;
        }

        self.cipher.encrypt(&mut self.tag);
        self.finished = true;

        self.tag.clone()
    }
}

impl<C: BlockCipher> Pmac<C> {
    /// Process a full internal buffer with a vectorized AES operation
    #[inline]
    fn process_buffer(&mut self) {
        for chunk in self.buffer.as_mut().chunks_mut(BLOCK_SIZE) {
            self.offset.xor_in_place(
                self.l[(self.counter + 1).trailing_zeros() as usize].as_ref(),
            );
            xor::in_place(chunk, self.offset.as_ref());

            self.counter = self.counter.checked_add(1).expect("overflow");
        }

        self.cipher.encrypt8(&mut self.buffer);

        for chunk in self.buffer.as_mut().chunks(BLOCK_SIZE) {
            self.tag.xor_in_place(&chunk);
        }

        self.buffer_pos = 0;
    }
}
