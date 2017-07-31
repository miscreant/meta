//! `internals/util/dbl.rs`: Reference implementation of dbl()
//!
//! This implementation is not guaranteed to be constant time, so we first compile it for a
//! particular architecture and then verify the generated assembly.
//!
//! See `dbl.asm` for the generated output.

use byteorder::{BigEndian, ByteOrder};
use super::BLOCK_SIZE;

/// Perform a doubling operation
pub fn dbl(value: &mut [u8; BLOCK_SIZE]) {
    let input = BigEndian::read_u128(value);
    let output = (input << 1) ^ (input >> 127) * 0b10000111;
    BigEndian::write_u128(value, output);
}
