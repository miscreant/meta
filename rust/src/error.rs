//! `error.rs`: Miscreant's error type

use core::fmt;

/// An opaque error type, used for all errors in Miscreant
#[derive(Debug, Eq, PartialEq)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "miscreant::error::Error")
    }
}
