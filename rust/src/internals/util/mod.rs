//! `internals/util/mod.rs`: Utility functions

use super::BLOCK_SIZE;
use byteorder::{BigEndian, ByteOrder};
use core::intrinsics;

/// Zero out the given slice
#[inline]
pub fn clear(value: &mut [u8]) {
    unsafe {
        // TODO: use a crate that provides this (e.g. clear_on_drop) instead of intrinsics
        intrinsics::volatile_set_memory(value.as_mut_ptr(), 0, value.len())
    }
}

/// Increment a CTR-mode counter. Panics on overflow
// TODO: use verified asm implementation?
pub fn ctr_increment(value: &mut [u8; BLOCK_SIZE]) {
    // This intentionally uses wrapping arithmetic as this is the correct
    // behavior for counter overflows.
    // TODO: verify we wrap at 128-bits and add test vectors which exercise it
    let output = BigEndian::read_u128(value) + 1;
    BigEndian::write_u128(value, output);
}

/// Perform an in-place doubling operation
#[inline]
pub fn dbl(value: &mut [u8; BLOCK_SIZE]) {
    unsafe {
        asm!(include_str!("dbl.asm")
            :
            : "rdi"(value)
            : "rax", "rcx", "rdx", "eax", "memory"
            : "intel"
        )
    }
}

/// XOR the second argument into the first in-place. Slices do not have to be
/// aligned in memory.
///
/// Panics if the two slices aren't the same length
pub fn xor_in_place(a: &mut [u8], b: &[u8]) {
    assert_eq!(a.len(), b.len(), "slices are not the same length!");

    for (b1, b2) in a.iter_mut().zip(b.iter()) {
        *b1 ^= *b2;
    }
}

/// Zero out the top bits in the last 32-bit words of the IV
pub fn zero_iv_bits(iv: &mut [u8; BLOCK_SIZE]) {
    let len = iv.len();

    // "We zero-out the top bit in each of the last two 32-bit words
    // of the IV before assigning it to Ctr"
    //  — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
    iv[len - 8] &= 0x7f;
    iv[len - 4] &= 0x7f;
}

#[cfg(test)]
mod tests {
    #[test]
    fn counter_increment() {
        let mut buffer = [0u8; 16];
        super::ctr_increment(&mut buffer);
        assert_eq!(buffer, *b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01");
    }

    #[test]
    #[should_panic]
    fn counter_overflow() {
        super::ctr_increment(&mut [0xFFu8; 16]);
    }
}
