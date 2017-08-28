# miscreant.go [![Build Status][build-shield]][build-link] [![GoDoc][godoc-shield]][godoc-link] [![Go Report Card][goreport-shield]][goreport-link] [![MIT licensed][license-shield]][license-link] [![Gitter Chat][gitter-image]][gitter-link]

[build-shield]: https://secure.travis-ci.org/miscreant/miscreant.svg?branch=master
[build-link]: http://travis-ci.org/miscreant/miscreant
[godoc-shield]: https://godoc.org/github.com/miscreant/miscreant/go?status.svg
[godoc-link]: https://godoc.org/github.com/miscreant/miscreant/go
[goreport-shield]: https://goreportcard.com/badge/github.com/miscreant/miscreant
[goreport-link]: https://goreportcard.com/report/github.com/miscreant/miscreant
[license-shield]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
[gitter-image]: https://badges.gitter.im/badge.svg
[gitter-link]: https://gitter.im/miscreant/Lobby

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

Go implementation of **Miscreant**: Advanced symmetric encryption using the
[AES-SIV] ([RFC 5297]) and [CHAIN/STREAM] constructions, providing easy-to-use
(or rather, hard-to-misuse) encryption of individual messages or message
streams.

**AES-SIV** provides [nonce-reuse misuse-resistance] (NRMR): accidentally
reusing a nonce with this construction is not a security catastrophe,
unlike it is with more popular AES encryption modes like [AES-GCM].
With **AES-SIV**, the worst outcome of reusing a nonce is an attacker
can see you've sent the same plaintext twice, as opposed to almost all other
AES modes where it can facilitate [chosen ciphertext attacks] and/or
full plaintext recovery.

For more information, see the [toplevel README.md].

[Phil Rogaway]: https://en.wikipedia.org/wiki/Phillip_Rogaway
[AES-SIV]: https://www.iacr.org/archive/eurocrypt2006/40040377/40040377.pdf
[RFC 5297]: https://tools.ietf.org/html/rfc5297
[CHAIN/STREAM]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf
[nonce-reuse misuse-resistance]: https://www.lvh.io/posts/nonce-misuse-resistance-101.html
[AES-GCM]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[chosen ciphertext attacks]: https://en.wikipedia.org/wiki/Chosen-ciphertext_attack
[toplevel README.md]: https://github.com/miscreant/miscreant/blob/master/README.md

## Help and Discussion

Have questions? Want to suggest a feature or change?

* [Gitter]: web-based chat about miscreant projects including **miscreant.go**
* [Google Group]: join via web or email ([miscreant-crypto+subscribe@googlegroups.com])

[Gitter]: https://gitter.im/miscreant/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/miscreant-crypto
[miscreant-crypto+subscribe@googlegroups.com]: mailto:miscreant-crypto+subscribe@googlegroups.com?subject=subscribe

## Security Notice

Though this library is written by cryptographic professionals, it has not
undergone a thorough security audit, and cryptographic professionals are still
humans that make mistakes.

This library makes an effort to use constant time operations throughout its
implementation, however actual constant time behavior has not been verified.

Use this library at your own risk.

## API

### Symmetric Encryption (AEAD)

**Miscreant** implements the [cipher.AEAD] interface which provides
[Authenticated Encryption with Associated Data]. This is the main API you
should use for most purposes unless you have highly specific needs that are
covered more specifically by one of the other APIs described below.

#### Creating a cipher instance: `newAEAD()`

To initialize a `cipher.AEAD`, you will need to select one of the ciphers
below to initialize it with:

* `"AES-SIV"`: CMAC-based construction described in [RFC 5297]. Slower but
  standardized and more common.
* `"AES-PMAC-SIV"`: PMAC-based construction. Faster but non-standardized and
  only available in the Miscreant libraries.

For performance reasons we recommend **AES-PMAC-SIV** but please be aware it
is only implemented by the Miscreant libraries.

After selecting a cipher, pass in a 32-byte or 64-byte key. Note that these
options are twice the size of what you might be expecting (AES-SIV uses two
AES keys).

You can generate a random key using the `miscreant.generateKey()` method, and
then instantiate a cipher instance by calling `miscreant.newAEAD()`. You will
also need to supply a nonce size. We recommend 16-bytes if you would like to
use random nonces:

```go
// Create a 32-byte AES-SIV key
k := miscreant.GenerateKey(32)

// Create a new cipher.AEAD instance
c := miscreant.newAEAD("AES-PMAC-SIV", k, 16)
```

[cipher.AEAD]: https://golang.org/pkg/crypto/cipher/#AEAD
[Authenticated Encryption with Associated Data]: https://en.wikipedia.org/wiki/Authenticated_encryption

#### Encrypting data: `Seal()`

The `Seal()` method encrypts a message and authenticates a bytestring of
*associated data* under a given key and nonce.

The `miscreant.GenerateNonce()` function can be used to randomly generate a
nonce for the message to be encrypted under. If you wish to use this approach
(alternatively you can use a counter for the nonce), please make sure to pass
a `nonceSize` of 16-bytes or greater to `newAEAD()`.

Example:

```go
import "github.com/miscreant/miscreant/go"

// Create a 32-byte AES-SIV key
k := miscreant.GenerateKey(32)

// Create a new cipher.AEAD instance with PMAC as the MAC
c := miscreant.newAEAD("AES-PMAC-SIV", k, 16)

// Plaintext to be encrypted
pt := []byte("Hello, world!")

// Nonce to encrypt it under
n := miscreant.GenerateNonce(c)

// Associated data to authenticate along with the message
// (or nil if we don't care)
ad := nil

// Create a destination buffer to hold the ciphertext. We need it to be the
// length of the plaintext plus `c.Overhead()` to hold the IV/tag
ct := make([]byte, len(pt) + c.Overhead())

// Perform encryption by calling 'Seal'. The encrypted ciphertext will be
// written into the `ct` buffer
c.Seal(ct, n, pt, ad)
```

#### Decryption (#open)

The `Open()` method decrypts a ciphertext with the given key.

Example:

```go
import "github.com/miscreant/miscreant/go"

// Load an existing cryptographic key
k := ...

// Create a new cipher.AEAD instance
c := miscreant.newAEAD("AES-PMAC-SIV", k, 16)

// Ciphertext to be decrypted
ct := ...

// Nonce under which the ciphertext was originally encrypted
n := ...

// Associated data to authenticate along with the message
// (or nil if we don't care)
ad := nil

// Create a destination buffer to hold the resulting plaintext.
// We need it to be the length of the ciphertext less `c.Overhead()`
l := len(ct) - c.Overhead()
if l < 0 {
    panic("ciphertext too short!")
}
pt := make([]byte, l)

// Perform decryption by calling 'Open'. The decrypted plaintext will be
// written into the `pt` buffer
_, err := c.Open(pt, n, ct, ad)
if err != nil {
    panic(err)
}
```

## Code of Conduct

We abide by the [Contributor Covenant][cc] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md].

[cc]: https://contributor-covenant.org
[CODE_OF_CONDUCT.md]: https://github.com/miscreant/miscreant/blob/master/CODE_OF_CONDUCT.md

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/miscreant/miscreant

## Copyright

Copyright (c) 2017 [The Miscreant Developers][AUTHORS].
See [LICENSE.txt] for further details.

[AUTHORS]: https://github.com/miscreant/miscreant/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
