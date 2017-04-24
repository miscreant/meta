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
Additionally, it provides streaming support, allowing large messages
to be incrementally encrypted/decrypted while still providing
[authenticated encryption].

The following constructions are provided by **SIVChain**:

* [AES-SIV]: (standardized in [RFC 5297]) combines the [AES-CTR] mode of
  encryption with the [AES-CMAC] function for integrity. Unlike most
  [authenticated encryption] algorithms, **AES-SIV** uses a
  MAC-then-encrypt construction, first using **AES-CMAC** to derive an
  IV from a MAC of zero or more "header" values and the message
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

## Comparison with other symmetric encryption algorithms

| Name              | [Authenticated Encryption] | [Nonce Reuse Misuse Resistance] | Standardization   |
|-------------------|----------------------------|---------------------------------|-------------------|
| AES-CBC           | :broken_heart:             | :broken_heart:                  | [NIST SP 800-38A] |
| AES-CTR           | :broken_heart:             | :broken_heart:                  | [NIST SP 800-38A] |
| AES-GCM           | :green_heart:              | :broken_heart:                  | [NIST SP 800-38D] |
| AES-GCM-SIV       | :green_heart:              | :green_heart:†                  | Forthcoming‡      |
| AES-SIV           | :green_heart:              | :green_heart:                   | [RFC 5297]        |
| ChaCha20+Poly1305 | :green_heart:              | :broken_heart:                  | [RFC 7539]        |
| XSalsa20+Poly1305 | :green_heart:              | :broken_heart:                  | None              |

† Previous drafts of the AES-GCM-SIV specification were vulnerable to [key recovery attacks]. 
  These attacks are being addressed in newer drafts of the specification.

‡ Work is underway in the IRTF CFRG to provide an informational RFC for AES-GCM-SIV.
  For more information, see [draft-irtf-cfrg-gcmsiv][AES-GCM-SIV].

When standardization work around [AES-GCM-SIV] is complete, it will seriously
considered for inclusion in this library. **AES-GCM-SIV** has the advantage of
the [GHASH] function being able to run in parallel, versus **AES-CMAC**'s
sequential operation.

**AES-SIV** has the advantage that it can be implemented using the AES
function alone, making it a better choice for environments where a
hardware accelerated version of the **GHASH** function is unavailable.

[NIST SP 800-38A]: https://dx.doi.org/10.6028/NIST.SP.800-38A
[NIST SP 800-38D]: http://dx.doi.org/10.6028/NIST.SP.800-38D
[RFC 7539]: https://tools.ietf.org/html/rfc7539
[key recovery attacks]: https://mailarchive.ietf.org/arch/attach/cfrg/pdfL0pM_N.pdf
[AES-GCM-SIV]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-gcmsiv/
[GHASH]: https://en.wikipedia.org/wiki/Galois/Counter_Mode#Mathematical_basis

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

## AES-SIV

This section provides a more in-depth exploration of how the **AES-SIV**
function operates.

### Encryption

<img src="https://camo.githubusercontent.com/3c23577a845b2ce86554dfc69b18cbbd691fd7cb/68747470733a2f2f7777772e7a637265642e6f72672f736976636861696e2f696d616765732f7369762d656e63727970742e737667" data-canonical-src="https://www.zcred.org/sivchain/images/siv-encrypt.svg" width="410px" height="300px">

#### Inputs:

* **AES-CMAC** and **AES-CTR** *keys*: *K<sub>1</sub>* and *K<sub>2</sub>*
* Zero or more message *headers*: *H<sub>1</sub>* through *H<sub>m</sub>*
* Plaintext *message*: *M*

#### Outputs:

* Initialization vector: *IV*
* *Ciphertext* message: *C*

#### Description:

**AES-SIV** first computes **AES-CMAC** on the message headers *H<sub>1</sub>*
through *H<sub>m</sub>* and messages under *K<sub>1</sub>*, computing a
*synthetic IV* (SIV). This IV is used to perform **AES-CTR** encryption under
*K<sub>2</sub>*

### Decryption

<img src="https://camo.githubusercontent.com/b2b2da0d26fccb4397e30b7555c7a0ace9df7737/68747470733a2f2f7777772e7a637265642e6f72672f736976636861696e2f696d616765732f7369762d646563727970742e737667" data-canonical-src="https://www.zcred.org/sivchain/images/siv-decrypt.svg" width="410px" height="368px">

#### Inputs:

* **AES-CMAC** and **AES-CTR** *keys*: *K<sub>1</sub>* and *K<sub>2</sub>*
* Zero or more message *headers*: *H<sub>1</sub>* through *H<sub>m</sub>*
* Initialization vector: *IV*
* *Ciphertext* message: *C*

#### Outputs:

* Plaintext *message*: *M*

#### Description:

To decrypt a message, **AES-SIV** first performs an **AES-CTR** decryption of
the message under the provided synthetic IV. The message headers
*H<sub>1</sub>* through *H<sub>m</sub>* and candidate decryption message are
then authenticated by **AES-CMAC**. If the computed `IV’` does not match the
original one supplied, the decryption operation is aborted. Otherwise, we've
authenticated the original plaintext and can return it.

## CHAIN

The CHAIN construction, originally described in the paper
[Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance][CHAIN],
provides a segmented [authenticated encryption] scheme while still providing
[nonce reuse misuse resistance]. This makes it suitable for use cases that
require incremental processing, such as large file encryption, transport
encryption, or other "streaming" use cases.

![CHAIN Diagram](http://www.zcred.org/sivchain/images/chain.svg)

## Copyright

Copyright (c) 2017 [The Zcred Developers][AUTHORS].
See [LICENSE.txt] for further details.

[AUTHORS]: https://github.com/zcred/zcred/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/zcred/sivchain/blob/master/LICENSE.txt
