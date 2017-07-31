//! `internals/util.rs`: Utility functions

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
