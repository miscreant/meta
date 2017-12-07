//! `s2v.rs`: a multi-message PRF construction built from a single-message PRF
//!
//! From "Deterministic Authenticated-Encryption: A Provable-Security Treatment
//! of the Key-Wrap Problem"[1]
//!
//! [1]: http://web.cs.ucdavis.edu/~rogaway/papers/keywrap.pdf

use crypto_mac::Mac;
use dbl::Dbl;
use generic_array::GenericArray;
use generic_array::typenum::{U16, Unsigned};

/// Maximum number of associated data items
pub const MAX_ASSOCIATED_DATA: usize = 126;

/// The S2V construction turns a pseudo-random function (e.g. CMAC, PMAC)
/// into a PRF that acts on a sequence of messages.
///
/// It's used by the SIV construction to derive a synthetic initialization
/// vector from zero or more message headers and the input plaintext.
pub fn s2v<M, I, T>(mac: &mut M, headers: I, message: &[u8]) -> GenericArray<u8, U16>
where
    M: Mac<OutputSize = U16>,
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    mac.input(&GenericArray::<u8, M::OutputSize>::default());
    let mut state = mac.result().code();

    for (i, header) in headers.into_iter().enumerate() {
        if i >= MAX_ASSOCIATED_DATA {
            panic!("too many associated data items!");
        }

        state = state.dbl();
        mac.input(header.as_ref());
        let code = mac.result().code();
        xor_in_place(&mut state, &code);
    }

    if message.len() >= M::OutputSize::to_usize() {
        let n = message
            .len()
            .checked_sub(M::OutputSize::to_usize())
            .unwrap();
        mac.input(&message[..n]);
        xor_in_place(&mut state, &message[n..]);
    } else {
        state = state.dbl();
        xor_in_place(&mut state, message);
        state[message.len()] ^= 0x80;
    };

    mac.input(state.as_ref());
    mac.result().code()
}

/// XOR the second argument into the first in-place. Slices do not have to be
/// aligned in memory.
///
/// Panics if the two slices aren't the same length
#[inline]
fn xor_in_place(a: &mut [u8], b: &[u8]) {
    for i in 0..b.len() {
        a[i] ^= b[i];
    }
}
