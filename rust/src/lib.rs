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
#![feature(repr_align)]

#[macro_use]
extern crate arrayref;
extern crate byteorder;
extern crate clear_on_drop;
extern crate subtle;

// TODO: reduce visibility by gating it on e.g. #[cfg(debug_assertions)]
pub mod internals;
pub mod siv;

pub use siv::{Aes128Siv, Aes256Siv};
