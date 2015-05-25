siv
===

[![Build Status](https://travis-ci.org/dchest/siv.svg)](https://travis-ci.org/dchest/siv)

Package siv implements Synthetic Initialization Vector (SIV) authenticated
encryption using AES (AES-SIV) as specified in RFC 5297.

It provides both the proper SIV interface with the ability to pass multiple
associated data items, and the standard nonce-based, single authentication
data cipher.AEAD.
