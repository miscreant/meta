//! `Miscreant`: Misuse-resistant symmetric encryption using the AES-SIV (RFC 5297) and
//! CHAIN/STREAM constructions.

#![crate_name = "miscreant"]
#![crate_type = "lib"]

#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]

#![no_std]

// Experimental features
// TODO: make crate work on stable
#![feature(i128_type)]
#![feature(asm)]
#![feature(attr_literals)]
#![cfg_attr(feature = "bench", feature(test))]

#[cfg(all(feature = "bench", test))]
extern crate test;

extern crate aesni;
#[macro_use]
extern crate arrayref;
extern crate byteorder;
extern crate block_cipher_trait;
extern crate clear_on_drop;
extern crate cmac;
extern crate crypto_mac;
extern crate dbl;
extern crate pmac;
extern crate subtle;

#[cfg(feature = "bench")]
mod bench;
mod ctr;
pub mod siv;

pub use siv::{Aes128Siv, Aes256Siv, Aes128PmacSiv, Aes256PmacSiv};
