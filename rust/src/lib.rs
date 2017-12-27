//! `Miscreant`: Misuse resistant symmetric encryption library providing the
//! AES-SIV (RFC 5297), AES-PMAC-SIV, and STREAM constructions

#![crate_name = "miscreant"]
#![crate_type = "lib"]

#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "bench", feature(test))]
#![cfg_attr(feature = "staticlib", feature(lang_items))]

extern crate aesni;
extern crate byteorder;
extern crate block_cipher_trait;
extern crate clear_on_drop;
extern crate cmac;
extern crate crypto_mac;
extern crate dbl;
extern crate generic_array;
extern crate pmac;
extern crate subtle;

#[cfg(feature = "std")]
extern crate core;

#[cfg(all(feature = "bench", test))]
extern crate test;

pub mod aead;
mod ctr;
pub mod error;
pub mod ffi;
pub mod siv;
mod s2v;
pub mod stream;

#[cfg(feature = "bench")]
mod bench;

// no_std boilerplate for building a static library
#[cfg(feature = "staticlib")]
#[allow(unsafe_code)]
#[lang = "panic_fmt"]
extern "C" fn panic_fmt(_args: ::core::fmt::Arguments, _file: &'static str, _line: u32) -> ! {
    loop {}
}
