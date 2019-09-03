# <img alt="miscreant." src="https://miscreant.io/images/miscreant.svg">

[![MIT Licensed][license-image]][license-link]
[![Gitter Chat][gitter-image]][gitter-link]

[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
[gitter-image]: https://badges.gitter.im/badge.svg
[gitter-link]: https://gitter.im/miscreant/Lobby

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

A misuse resistant symmetric encryption library designed to support
authenticated encryption of individual messages, encryption keys,
message streams, or large files using the [AES-SIV] ([RFC 5297]),
[AES-PMAC-SIV], and [STREAM] constructions.

Miscreant is available for several programming languages, including
[C#], [Go], [JavaScript], [Python], [Ruby], and [Rust].

[Phil Rogaway]: https://en.wikipedia.org/wiki/Phillip_Rogaway
[RFC 5297]: https://tools.ietf.org/html/rfc5297
[AES-SIV]: https://github.com/miscreant/miscreant/wiki/AES-SIV
[AES-PMAC-SIV]: https://github.com/miscreant/miscreant/wiki/AES-PMAC-SIV
[STREAM]: https://github.com/miscreant/miscreant/wiki/STREAM
[C#]: https://github.com/miscreant/miscreant/tree/master/dotnet
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

The following algorithms are provided by **Miscreant**:

* [AES-SIV]: an [authenticated] mode of AES which provides
  [nonce reuse misuse resistance]. Described in [RFC 5297], it combines the
  [AES-CTR] ([NIST SP 800-38A]) mode of encryption with the
  [AES-CMAC]([NIST SP 800-38B]) function for integrity.

* [AES-PMAC-SIV]: a fully parallelizable variant of **AES-SIV** which
  substitutes the [AES-PMAC] function for integrity, providing effectively
  identical security properties as the original construction, but much better
  performance on systems which provide parallel hardware implementations of
  AES, namely Intel/AMD CPUs.

* [STREAM]: a construction which, when combined with **AES-SIV** or
  **AES-PMAC-SIV**, provides online/streaming [authenticated] encryption
  and defends against reordering and truncation attacks.

[authenticated]: https://en.wikipedia.org/wiki/Authenticated_encryption
[nonce reuse misuse resistance]: https://github.com/miscreant/miscreant/wiki/Nonce-Reuse-Misuse-Resistance
[AES-CTR]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29
[AES-CMAC]: https://en.wikipedia.org/wiki/One-key_MAC
[AES-PMAC]: http://web.cs.ucdavis.edu/~rogaway/ocb/pmac-bak.htm

## Cipher Comparison

### Miscreant Ciphers

| Name              | [Authenticated] | [Misuse Resistance] | x86 Speed      | IoT Speed† | Standardization   |
|-------------------|-----------------|---------------------|----------------|------------|-------------------|
| [AES-SIV]         | 💚              | 💚                  | 💛             | 💚         | [RFC 5297]        |
| [AES-PMAC-SIV]    | 💚              | 💚                  | 💚             | 💚         | None              |

### Other Constructions

| Name              | [Authenticated] | [Misuse Resistance] | x86 Speed      | IoT Speed† | Standardization   |
|-------------------|-----------------|---------------------|----------------|------------|-------------------|
| AES-GCM-SIV       | 💚              | 💚                  | 💖             | 💔         | Forthcoming‡      |
| AES-GCM           | 💚              | 💔                  | 💖             | 💔         | [NIST SP 800-38D] |
| AES-CCM           | 💚              | 💔                  | 💛             | 💚         | [NIST SP 800-38C] |
| AES-CBC           | 💔              | 💔                  | 💚             | 💚         | [NIST SP 800-38A] |
| AES-CTR           | 💔              | 💔                  | 💚             | 💚         | [NIST SP 800-38A] |
| ChaCha20+Poly1305 | 💚              | 💔                  | 💚             | 💛         | [RFC 7539]        |
| XSalsa20+Poly1305 | 💚              | 💔                  | 💚             | 💛         | None              |

### Legend

| Heart | Meaning   |
|-------|-----------|
| 💚    | Great     |
| 💛    | Fine <img src="https://raw.githubusercontent.com/miscreant/miscreant.github.io/master/images/thisisfine.png" width="16" height="16"> |
| 💔    | Bad       |

† Assumes hardware acceleration for the AES block cipher function

‡ Work is underway in the IRTF CFRG to provide an informational RFC for **AES-GCM-SIV**.
  For more information, see [draft-irtf-cfrg-gcmsiv].
  When standardization work around **AES-GCM-SIV** is complete, it will be
  [considered for inclusion in this library](https://github.com/miscreant/miscreant/issues/60).

[Misuse Resistance]: https://github.com/miscreant/miscreant/wiki/Nonce-Reuse-Misuse-Resistance
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
| [C#][nuget-link]       | [![nuget][nuget-shield]][nuget-link] |
| [Go][go-link]          | N/A                                  |
| [JavaScript][npm-link] | [![npm][npm-shield]][npm-link]       |
| [Python][pypi-link]    | [![pypi][pypi-shield]][pypi-link]    |
| [Ruby][gem-link]       | [![gem][gem-shield]][gem-link]       |
| [Rust][crate-link]     | [![crate][crate-shield]][crate-link] |

[nuget-link]: https://www.nuget.org/packages/Miscreant
[nuget-shield]: https://img.shields.io/nuget/v/Miscreant.svg
[go-link]: https://github.com/miscreant/miscreant/tree/master/go
[npm-shield]: https://img.shields.io/npm/v/miscreant.svg
[npm-link]: https://www.npmjs.com/package/miscreant
[pypi-shield]: https://img.shields.io/pypi/v/miscreant.svg
[pypi-link]: https://pypi.python.org/pypi/miscreant/
[gem-shield]: https://badge.fury.io/rb/miscreant.svg
[gem-link]: https://rubygems.org/gems/miscreant
[crate-shield]: https://img.shields.io/crates/v/miscreant.svg
[crate-link]: https://crates.io/crates/miscreant

## Documentation

[Please see the Miscreant Wiki](https://github.com/miscreant/miscreant/wiki)
for more detailed documentation and usage notes.

## Related Projects

* [XSTREAM]: public-key cryptography built on Miscreant and the [X25519]
  elliptic curve Diffie-Hellman function.
* [minc] (the MIscreaNt Cryptotool): a command-line encryption utility built
  on Miscreant and **XSTREAM**.

[XSTREAM]: https://github.com/miscreant/xstream
[X25519]: https://en.wikipedia.org/wiki/Curve25519
[minc]: https://github.com/miscreant/minc

## Help and Discussion

Have questions? Want to suggest a feature or change?

* [Gitter]: web-based chat about Miscreant
* [Google Group]: join via web or email ([miscreant-crypto+subscribe@googlegroups.com])

[Gitter]: https://gitter.im/miscreant/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/miscreant-crypto
[miscreant-crypto+subscribe@googlegroups.com]: mailto:miscreant-crypto+subscribe@googlegroups.com?subject=subscribe

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

Copyright (c) 2017-2018 [The Miscreant Developers][AUTHORS].
Distributed under the MIT license. See [LICENSE.txt] for further details.

Some language-specific subprojects include sources from other authors with more
specific licensing requirements, though all projects are MIT licensed.
Please see the respective **LICENSE.txt** files in each project for more
information.

[AUTHORS]: https://github.com/miscreant/miscreant/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
