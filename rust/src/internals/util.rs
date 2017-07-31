//! `internals/util.rs`: Utility functions

use super::BLOCK_SIZE;

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
