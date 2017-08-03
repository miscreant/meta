//! `internals/block.rs`: Functions for working on cipher blocks.
//!
//! Special-cased for AES's 128-bit block size

use byteorder::{BigEndian, NativeEndian, ByteOrder};
use core::{intrinsics, ptr};
use subtle::{self, CTEq, Mask};

/// All constructions are presently specialized to a 128-bit block size (i.e. the AES block size)
pub const SIZE: usize = 16;

/// A block acceptable to pass to a block cipher (i.e. memory aligned)
#[derive(Clone, Default)]
#[repr(align(16))]
pub struct Block([u8; SIZE]);

impl Block {
    /// Create a new block, initialized to zero
    pub fn new() -> Block {
        Block([0u8; SIZE])
    }

    /// XOR the other block into this one
    #[inline]
    pub fn xor_in_place<T>(&mut self, other: T)
    where
        T: AsRef<[u8]>,
    {
        // TODO: find a way to eliminate this assertion with type safety
        assert_eq!(
            other.as_ref().len(),
            SIZE,
            "xor_in_place works on block-sized slices"
        );

        let x: u128 = NativeEndian::read_u128(&self.0);
        let y: u128 = NativeEndian::read_u128(other.as_ref());

        NativeEndian::write_u128(&mut self.0, x ^ y);
    }

    /// Copy the contents of the other block into this one
    ///
    /// Panics if the two blocks are the same
    #[inline]
    pub fn copy_from_block(&mut self, other: &Block) {
        assert_ne!(self.0.as_ptr(), other.0.as_ptr(), "can't copy self");
        unsafe { ptr::copy_nonoverlapping(&other.0, &mut self.0, SIZE) }
    }

    /// Zero out the contents of the block
    #[inline]
    pub fn clear(&mut self) {
        unsafe {
            // TODO: use a crate that provides this (e.g. clear_on_drop) instead of intrinsics
            intrinsics::volatile_set_memory(self.0.as_mut_ptr(), 0, SIZE)
        }
    }

    /// Performs a doubling operation as defined in the CMAC and SIV papers
    #[inline]
    pub fn dbl(&mut self) {
        let input = BigEndian::read_u128(&self.0);
        let output = (input << 1) ^ ((input >> 127) * 0b1000_0111);
        BigEndian::write_u128(&mut self.0, output);
    }
}

impl From<[u8; SIZE]> for Block {
    #[inline]
    fn from(buf: [u8; SIZE]) -> Block {
        Block(buf)
    }
}

impl<'a> From<&'a [u8]> for Block {
    #[inline]
    fn from(buf: &[u8]) -> Block {
        let len = buf.len();

        if len > SIZE {
            panic!("slice is too large for block! (size: {})", buf.len());
        }

        let mut block = Block::new();
        block.0[..len].copy_from_slice(buf);
        block
    }
}

impl AsRef<[u8]> for Block {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8; SIZE]> for Block {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8; SIZE] {
        &mut self.0
    }
}

impl Drop for Block {
    #[inline]
    fn drop(&mut self) {
        self.clear()
    }
}

impl CTEq for Block {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Mask {
        subtle::arrays_equal(&self.0, &other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::Block;

    #[test]
    fn test_xor_in_place() {
        let mut block1 = Block::from(
            *b"\x17\xcc\xf7\xf7\xa1\x8c\xbc\x3d\x8d\xad\0\xf1\xc9\x79\x9f\xba",
        );

        let block2 = Block::from(
            *b"\x8d\xa8\xd5\x40\x7c\x9a\x62\xa0\x7b\x89\x94\x39\x3a\x84\xf1\x6b",
        );

        block1.xor_in_place(&block2);
        assert_eq!(
            block1.as_ref(),
            b"\x9a\x64\x22\xb7\xdd\x16\xde\x9d\xf6\x24\x94\xc8\xf3\xfd\x6e\xd1"
        );
    }
}
