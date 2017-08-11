//! `internals/mac.rs`: Message Authentication Codes (MACs)

use super::{Block, BlockCipher};

/// Trait for Message Authentication Codes (MACs)
pub trait Mac<C: BlockCipher> {
    /// Create a new MAC instance with the given cipher
    fn new(cipher: C) -> Self;

    /// Reset a MAC instance back to its initial state
    fn reset(&mut self);

    /// Update the MAC's internal state with the given message
    fn update(&mut self, msg: &[u8]);

    /// Finish computing the MAC, returning the computed tag (i.e. checksum) as a `Block`
    fn finish(&mut self) -> Block;
}
