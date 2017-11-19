//! `internals/mac/mod.rs`: Message Authentication Codes (MACs)

mod cmac;
mod pmac;

pub use self::cmac::{Aes128Cmac, Aes256Cmac};
pub use self::pmac::{Aes128Pmac, Aes256Pmac};
use super::Block;

/// Trait for Message Authentication Codes (MACs)
pub trait Mac {
    /// Reset a MAC instance back to its initial state
    fn reset(&mut self);

    /// Update the MAC's internal state with the given message
    fn update(&mut self, msg: &[u8]);

    /// Finish computing the MAC, returning the computed tag (i.e. checksum) as a `Block`
    fn finish(&mut self) -> Block;
}
