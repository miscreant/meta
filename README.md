# <img alt="miscreant." src="https://miscreant.io/images/miscreant.svg">

[![Build Status][build-image]][build-link]
[![MIT Licensed][license-image]][license-link]
[![Gitter Chat][gitter-image]][gitter-link]

[build-image]: https://secure.travis-ci.org/miscreant/miscreant.svg?branch=master
[build-link]: http://travis-ci.org/miscreant/miscreant
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
[gitter-image]: https://badges.gitter.im/badge.svg
[gitter-link]: https://gitter.im/miscreant/Lobby

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

A misuse resistant symmetric encryption library designed to support
authenticated encryption of individual messages, encryption keys,
message streams, or large files using the [AES-SIV] ([RFC 5297]) and
[CHAIN/STREAM] constructions.

Miscreant is available for several programming languages, including
[Go], [JavaScript], [Python], [Ruby], and [Rust].

[Phil Rogaway]: https://en.wikipedia.org/wiki/Phillip_Rogaway
[RFC 5297]: https://tools.ietf.org/html/rfc5297
[CHAIN/STREAM]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf
[Go]: https://github.com/miscreant/miscreant/tree/master/go
[JavaScript]: https://github.com/miscreant/miscreant/tree/master/js
[Python]: https://github.com/miscreant/miscreant/tree/master/python
[Ruby]: https://github.com/miscreant/miscreant/tree/master/ruby
[Rust]: https://github.com/miscreant/miscreant/tree/master/rust

## What is Miscreant?

**Miscreant** is a set of interoperable libraries implemented in several
languages providing a high-level API for misuse-resistant symmetric encryption.
Additionally, it provides support for "online" [authenticated encryption] use
cases such as streaming or incrementally encryption/decryption of large files.

The following constructions are provided by **Miscreant**:

* [AES-SIV]: (standardized in [RFC 5297]) combines the [AES-CTR]
  ([NIST SP 800-38A]) mode of encryption with the [AES-CMAC]
  ([NIST SP 800-38B]) or [AES-PMAC] function for integrity.
  Unlike most [authenticated encryption] algorithms, **AES-SIV** uses a
  special "encrypt-with-MAC" construction which combines the roles of an
  initialization vector (IV) with a message authentication code (MAC)
  using a construction called a *synthetic initialization vector* (SIV).
  It works in practice by first using **AES-CMAC** or **AES-PMAC** to derive
  an IV from a MAC of zero or more "header" values and the message
  plaintext, then encrypting the message under that derived IV.
  This approach provides not just the benefits of an authenticated
  encryption mode, but also makes it resistant to accidental reuse
  of an IV/nonce, something that would be catastrophic with a mode
  like **AES-GCM**. **AES-SIV** provides [nonce reuse misuse resistance],
  considered the gold standard in cryptography today.

* [CHAIN]: a construction which provides "online" chunked/multipart
  [authenticated encryption] when used in conjunction with a cipher like
  **AES-SIV**. **CHAIN** achieves the best-possible security for an online
  authenticated encryption scheme (OAE2).

* [STREAM]: a construction which provides streaming [authenticated encryption]
  and defends against reordering and truncation attacks. Unlike **CHAIN**,
  **STREAM** supports parallelization and seeking, allowing chunks within
  a message to be encrypted and decrypted in any order the user wants.
  **STREAM** provides nonce-based online authenticated encryption (nOAE),
  which the [CHAIN/STREAM] paper proves is equivalent to OAE2.

Though not yet described in an RFC, **CHAIN** and **STREAM** were designed by
[Phil Rogaway] (who also created **AES-SIV**) and are described in the paper
[Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance], which
contains a rigorous security analysis proving them secure under the definitions
of OAE2 and nOAE respectively.

_NOTE:_ this library does not yet support **CHAIN** and **STREAM**! Please see
the tracking issues [CHAIN support (OAE2)] and [STREAM support (Nonce-based OAE)]
to follow progress on adding support.

[authenticated encryption]: https://en.wikipedia.org/wiki/Authenticated_encryption
[AES-SIV]: https://www.iacr.org/archive/eurocrypt2006/40040377/40040377.pdf
[AES-CTR]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29
[AES-CMAC]: https://en.wikipedia.org/wiki/One-key_MAC
[AES-PMAC]: http://web.cs.ucdavis.edu/~rogaway/ocb/pmac-bak.htm
[nonce reuse misuse resistance]: https://www.lvh.io/posts/nonce-misuse-resistance-101.html
[misuse resistant]: https://www.lvh.io/posts/nonce-misuse-resistance-101.html
[CHAIN]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf
[STREAM]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf
[Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf
[CHAIN support (OAE2)]: https://github.com/miscreant/miscreant/issues/33
[STREAM support (Nonce-based OAE)]: https://github.com/miscreant/miscreant/issues/32


## Help and Discussion

Have questions? Want to suggest a feature or change?

* [Gitter]: web-based chat about Miscreant
* [Google Group]: join via web or email ([miscreant-crypto+subscribe@googlegroups.com])

[Gitter]: https://gitter.im/miscreant/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/miscreant-crypto
[miscreant-crypto+subscribe@googlegroups.com]: mailto:miscreant-crypto+subscribe@googlegroups.com?subject=subscribe


## Cipher Comparison

### Miscreant Ciphers

| Name              | [Authenticated Encryption] | [Misuse Resistance] | Performance        | Standardization   |
|-------------------|----------------------------|---------------------|--------------------|-------------------|
| AES-SIV           | :green_heart:              | :green_heart:       | :yellow_heart:     | [RFC 5297]        |
| AES-PMAC-SIV      | :green_heart:              | :green_heart:       | :green_heart:      | None              |

### Other Constructions

| Name              | [Authenticated Encryption] | [Misuse Resistance] | Performance        | Standardization   |
|-------------------|----------------------------|---------------------|--------------------|-------------------|
| AES-GCM-SIV       | :green_heart:              | :green_heart:       | :green_heart:      | Forthcoming†      |
| AES-GCM           | :green_heart:              | :broken_heart:      | :green_heart:      | [NIST SP 800-38D] |
| AES-CCM           | :green_heart:              | :broken_heart:      | :yellow_heart:     | [NIST SP 800-38C] |
| AES-CBC           | :broken_heart:             | :broken_heart:      | :green_heart:      | [NIST SP 800-38A] |
| AES-CTR           | :broken_heart:             | :broken_heart:      | :green_heart:      | [NIST SP 800-38A] |
| ChaCha20+Poly1305 | :green_heart:              | :broken_heart:      | :green_heart:      | [RFC 7539]        |
| XSalsa20+Poly1305 | :green_heart:              | :broken_heart:      | :green_heart:      | None              |

### Legend

| Heart             | Meaning   |
|-------------------|-----------|
| :green_heart:     | Great     |
| :yellow_heart:    | Fine <img src="https://raw.githubusercontent.com/miscreant/miscreant.github.io/master/images/thisisfine.png" width="16" height="16"> |
| :broken_heart:    | Bad       |

† Work is underway in the IRTF CFRG to provide an informational RFC for AES-GCM-SIV.
  For more information, see [draft-irtf-cfrg-gcmsiv].
  When standardization work around **AES-GCM-SIV** is complete, it will be
  [considered for inclusion in this library](https://github.com/miscreant/miscreant/issues/60).

[Misuse Resistance]: https://www.lvh.io/posts/nonce-misuse-resistance-101.html
[NIST SP 800-38A]: https://dx.doi.org/10.6028/NIST.SP.800-38A
[NIST SP 800-38B]: https://dx.doi.org/10.6028/NIST.SP.800-38B
[NIST SP 800-38C]: https://dx.doi.org/10.6028/NIST.SP.800-38C
[NIST SP 800-38D]: https://dx.doi.org/10.6028/NIST.SP.800-38D
[RFC 7539]: https://tools.ietf.org/html/rfc7539
[draft-irtf-cfrg-gcmsiv]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-gcmsiv/
[GHASH]: https://en.wikipedia.org/wiki/Galois/Counter_Mode#Mathematical_basis


## Language Support

**Miscreant** libraries are available for the following languages:

| Language               | Version                              |
|------------------------|--------------------------------------|
| [Go][go-link]          | N/A                                  |
| [JavaScript][npm-link] | [![npm][npm-shield]][npm-link]       |
| [Python][pypi-link]    | [![pypi][pypi-shield]][pypi-link]    |
| [Ruby][gem-link]       | [![gem][gem-shield]][gem-link]       |
| [Rust][crate-link]     | [![crate][crate-shield]][crate-link] |

[go-link]: https://github.com/miscreant/miscreant/tree/master/go
[npm-shield]: https://img.shields.io/npm/v/miscreant.svg
[npm-link]: https://www.npmjs.com/package/miscreant
[pypi-shield]: https://img.shields.io/pypi/v/miscreant.svg
[pypi-link]: https://pypi.python.org/pypi/miscreant/
[gem-shield]: https://badge.fury.io/rb/miscreant.svg
[gem-link]: https://rubygems.org/gems/miscreant
[crate-shield]: https://img.shields.io/crates/v/miscreant.svg
[crate-link]: https://crates.io/crates/miscreant


## AES-SIV

This section provides a more in-depth exploration of how the **AES-SIV**
function operates.

### Encryption

<img src="https://miscreant.io/images/siv-encrypt.svg" width="410px" height="300px">

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

<img src="https://miscreant.io/images/siv-decrypt.svg" width="410px" height="368px">

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


## Code of Conduct

We abide by the [Contributor Covenant][cc] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md].

[cc]: https://contributor-covenant.org
[CODE_OF_CONDUCT.md]: https://github.com/miscreant/miscreant/blob/master/CODE_OF_CONDUCT.md

## Key Rap

The paper describing AES-SIV,
[Deterministic Authenticated-Encryption: A Provable-Security Treatment of the Key-Wrap Problem]
contains this explanatory rap song at the end, which goes out to all the
chronic IV misusing miscreants in the land:

> Yo! We’z gonna’ take them keys an’ whatever you pleaze<br>
> We gonna’ wrap ’em all up looks like some ran’om gup<br>
> Make somethin’ gnarly and funky won’t fool no half-wit junkie<br>
> So the game’s like AE but there’s one major hitch<br>
> No coins can be pitched there’s no state to enrich<br>
> the IV’s in a ditch dead drunk on cheap wine<br>
> Now NIST and X9 and their friends at the fort<br>
> suggest that you stick it in a six-layer torte<br>
> S/MIME has a scheme there’s even one more<br>
> So many ways that it’s hard to keep score<br>
> And maybe they work and maybe they’re fine<br>
> but I want some proofs for spendin’ my time<br>
> After wrappin’ them keys gonna’ help out some losers<br>
> chronic IV abusers don’t read no directions<br>
> risk a deadly infection If a rusty IV’s drippin’ into yo’ veins<br>
> and ya never do manage to get it exchanged<br>
> Then we got ya somethin’ and it comes at low cost<br>
> When you screw up again not all ’ill be lost

[Deterministic Authenticated-Encryption: A Provable-Security Treatment of the Key-Wrap Problem]: http://web.cs.ucdavis.edu/~rogaway/papers/keywrap.pdf

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/miscreant/miscreant

## Copyright

Copyright (c) 2017 [The Miscreant Developers][AUTHORS].
Distributed under the MIT license. See [LICENSE.txt] for further details.

Some language-specific subprojects include sources from other authors with more
specific licensing requirements, though all projects are MIT licensed.
Please see the respective **LICENSE.txt** files in each project for more
information.

[AUTHORS]: https://github.com/miscreant/miscreant/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
