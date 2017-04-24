# SIVChain for Go

Package sivchain implements Synthetic Initialization Vector (SIV) authenticated
encryption using AES (AES-SIV) as specified in RFC 5297.

It provides both the proper SIV interface with the ability to pass multiple
associated data items, and the standard nonce-based, single authentication
data cipher.AEAD.

**!!! DO NOT USE, NOT TESTED PROPERLY YET !!!**
