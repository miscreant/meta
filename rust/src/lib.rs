//! `Miscreant`: Misuse-resistant symmetric encryption using the AES-SIV (RFC 5297) and
//! CHAIN/STREAM constructions.

#![crate_name = "miscreant"]
#![crate_type = "lib"]

#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]

#![no_std]

#![cfg_attr(feature = "bench", feature(test))]
#[cfg(all(feature = "bench", test))]
extern crate test;

extern crate aesni;
extern crate block_cipher_trait;
extern crate clear_on_drop;
extern crate cmac;
extern crate crypto_mac;
extern crate dbl;
extern crate generic_array;
extern crate pmac;
extern crate subtle;

pub mod aead;
mod ctr;
pub mod siv;
mod s2v;

#[cfg(feature = "bench")]
mod bench;
