//! `error.rs`: Miscreant's error type

use core::fmt;

/// How to display the error type in messages
const DISPLAY_STRING: &str = "miscreant::error::Error";

/// An opaque error type, used for all errors in Miscreant
#[derive(Debug, Eq, PartialEq)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", DISPLAY_STRING)
    }
}

#[cfg(feature = "std")]
impl ::std::error::Error for Error {
    #[inline]
    fn description(&self) -> &str {
        DISPLAY_STRING
    }
}
