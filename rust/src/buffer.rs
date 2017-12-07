//! 'buffer.rs': A buffer type which handles slicing of AEAD messages

use core::fmt;

// TODO: use const generics when available
const TAG_SIZE: usize = 16;

/// A buffer type which handles taking slices of the message and tag portions
/// of AEAD messages. Intended to make the in-place API slightly easier to work
/// with and eliminate manual index calculations.
pub struct Buffer<T: AsRef<[u8]> + AsMut<[u8]>>(T);

// TODO: support for algorithms that place the tag at the end of the buffer
// instead of the beginning. That's pretty much every AEAD scheme except
// AES-SIV. Unfortunately AES-SIV is wacky that way.
impl<T> Buffer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// The entire message buffer as a slice
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// The entire message buffer as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }

    /// Slice of the buffer containing the message (i.e. plaintext or untagged ciphertext)
    pub fn msg_slice(&self) -> &[u8] {
        &self.as_slice()[TAG_SIZE..]
    }

    /// Mutable slice of the buffer containing the message (i.e. plaintext or untagged ciphertext)
    pub fn mut_msg_slice(&mut self) -> &mut [u8] {
        &mut self.as_mut_slice()[TAG_SIZE..]
    }

    /// Slice of the buffer containing the message tag
    pub fn tag_slice(&self) -> &[u8] {
        &self.as_slice()[..TAG_SIZE]
    }

    /// Mutable slice of the buffer containing the message tag
    pub fn mut_tag_slice(&mut self) -> &mut [u8] {
        &mut self.as_mut_slice()[..TAG_SIZE]
    }

    /// Obtain the original value this buffer wraps
    pub fn into_contents(self) -> T {
        self.0
    }
}

impl<T> From<T> for Buffer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Create a `Buffer` which wraps T.
    /// Panics if T is too small to contain the MAC tag
    fn from(value: T) -> Buffer<T> {
        assert!(
            value.as_ref().len() >= TAG_SIZE,
            "expected length of at least {}, got {}",
            TAG_SIZE,
            value.as_ref().len()
        );

        Buffer(value)
    }
}

impl<T> AsRef<[u8]> for Buffer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<T> AsMut<[u8]> for Buffer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl<T> fmt::Debug for Buffer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "miscreant::Buffer {{ {:?} }}", self.as_slice())
    }
}
