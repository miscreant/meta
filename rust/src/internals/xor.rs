//! `internals/xor.rs`: XOR as an in-place bytestring operation

/// XOR the second argument into the first in-place. Slices do not have to be
/// aligned in memory.
///
/// Panics if the two slices aren't the same length
pub fn in_place(a: &mut [u8], b: &[u8]) {
    debug_assert_eq!(a.len(), b.len(), "slices are not the same length!");

    for i in 0..a.len() {
        a[i] ^= b[i];
    }
}
