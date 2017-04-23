# SIVChain

[![Build Status][build-image]][build-link]
[![MIT licensed][license-image]][license-link]

[build-image]: https://secure.travis-ci.org/zcred/sivchain.svg?branch=master
[build-link]: http://travis-ci.org/zcred/sivchain
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/zcred/sivchain/blob/master/LICENSE.txt

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

Advanced symmetric encryption using the AES-SIV ([RFC 5297]) and [CHAIN] constructions,
providing easy-to-use (or rather, hard-to-misuse) encryption of individual
messages or message streams.

[Phil Rogaway]: https://en.wikipedia.org/wiki/Phillip_Rogaway
[RFC 5297]: https://tools.ietf.org/html/rfc5297
[CHAIN]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf

## What is SIVChain?

**SIVChain** is a set of interoperable libraries implemented in several
languages providing a high-level API for hard-to-misuse symmetric encryption.
Additionally, they provide streaming support, allowing large ciphertexts
to be incrementally encrypted/decrypted while still providing
[authenticated encryption].

The following constructions are provided by **SIVChain**:

* [AES-SIV]: (standardized in [RFC 5297]) combines the [AES-CTR] mode of
  encryption with the [AES-CMAC] function for integrity. Unlike most
  [authenticated encryption] algorithms, **AES-SIV** uses a
  MAC-then-encrypt construction, first using **AES-CMAC** to derive an
  IV from a MAC of zero or more "header" values and the message in
  plaintext, then encrypting the message under that derived IV.
  This approach provides not just the benefits of an authenticated
  encryption mode, but also makes it resistant to accidental reuse
  of an IV/nonce, something that would be catastrophic with a mode
  like **AES-GCM**. **AES-SIV** provides [nonce reuse misuse resistance],
  considered the gold standard in cryptography today.
 
 * [CHAIN]: a construction which provides streaming [authenticated encryption]
   when used in conjunction with a cipher like **AES-SIV** that supports
   [nonce reuse misuse resistance]. Though not yet described in an RFC,
   **CHAIN** was designed by Phil Rogaway (who also created **AES-SIV**)
   and the paper contains a rigorous security analysis proving it secure.

[authenticated encryption]: https://en.wikipedia.org/wiki/Authenticated_encryption
[AES-SIV]: https://www.iacr.org/archive/eurocrypt2006/40040377/40040377.pdf
[AES-CTR]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29
[AES-CMAC]: https://en.wikipedia.org/wiki/One-key_MAC
[nonce reuse misuse resistance]: https://www.lvh.io/posts/nonce-misuse-resistance-101.html

## Language Support

Packages implementing SIVChain are available for the following languages:

| Language               | Version                              |
|------------------------|--------------------------------------|
| [Go][go-link]          | N/A                                  |
| [JavaScript][npm-link] | [![npm][npm-shield]][npm-link]       |
| [Python][pypi-link]    | [![pypi][pypi-shield]][pypi-link]    |
| [Ruby][gem-link]       | [![gem][gem-shield]][gem-link]       |
| [Rust][crate-link]     | [![crate][crate-shield]][crate-link] |

[go-link]: https://github.com/zcred/sivchain/tree/master/go
[npm-shield]: https://img.shields.io/npm/v/sivchain.svg
[npm-link]: https://www.npmjs.com/package/sivchain
[pypi-shield]: https://img.shields.io/pypi/v/sivchain.svg
[pypi-link]: https://pypi.python.org/pypi/sivchain/
[gem-shield]: https://badge.fury.io/rb/sivchain.svg
[gem-link]: https://rubygems.org/gems/sivchain
[crate-shield]: https://img.shields.io/crates/v/sivchain.svg
[crate-link]: https://crates.io/crates/sivchain

## Copyright

Copyright (c) 2017 [The Zcred Developers][AUTHORS].
See [LICENSE.txt] for further details.

[AUTHORS]: https://github.com/zcred/zcred/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/zcred/sivchain/blob/master/LICENSE.txt
