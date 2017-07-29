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

[Phil Rogaway]: https://en.wikipedia.org/wiki/Phillip_Rogaway
[RFC 5297]: https://tools.ietf.org/html/rfc5297
[CHAIN/STREAM]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf


## What is Miscreant?

**Miscreant** is a set of interoperable libraries implemented in several
languages providing a high-level API for misuse-resistant symmetric encryption.
Additionally, it provides support for "online" [authenticated encryption] use
cases such as streaming or incrementally encryption/decryption of large files.

The following constructions are provided by **Miscreant**:

* [AES-SIV]: (standardized in [RFC 5297]) combines the [AES-CTR]
  ([NIST SP 800-38A]) mode of encryption with the [AES-CMAC]
  ([NIST SP 800-38B]) function for integrity.
  Unlike most [authenticated encryption] algorithms, **AES-SIV** uses a
  MAC-then-encrypt construction, first using **AES-CMAC** to derive an
  IV from a MAC of zero or more "header" values and the message
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
  **STREAM** achieves a slightly lower definition of security for an online
  encryption scheme (OAE1) as compared to **CHAIN**.

Though not yet described in an RFC, **CHAIN** and **STREAM** were designed by
[Phil Rogaway] (who also created **AES-SIV**) and are described in the paper
[Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance], which
contains a rigorous security analysis proving them secure under the definitions
of OAE2 and OAE1 respectively.

_NOTE:_ this library does not yet support **CHAIN** and **STREAM**! Please see
the tracking issues [CHAIN support (OAE2)] and [STREAM support (Nonce-based OAE)]
to follow progress on adding support.

[authenticated encryption]: https://en.wikipedia.org/wiki/Authenticated_encryption
[AES-SIV]: https://www.iacr.org/archive/eurocrypt2006/40040377/40040377.pdf
[AES-CTR]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29
[AES-CMAC]: https://en.wikipedia.org/wiki/One-key_MAC
[nonce reuse misuse resistance]: https://www.lvh.io/posts/nonce-misuse-resistance-101.html
[misuse resistant]: https://www.lvh.io/posts/nonce-misuse-resistance-101.html
[CHAIN]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf
[STREAM]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf
[Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf
[CHAIN support (OAE2)]: https://github.com/miscreant/miscreant/issues/33
[STREAM support (Nonce-based OAE)]: https://github.com/miscreant/miscreant/issues/32


## Comparison of AES-SIV to other symmetric encryption ciphers

| Name              | [Authenticated Encryption] | [Misuse Resistance] | Passes | Standardization   |
|-------------------|----------------------------|---------------------|--------|-------------------|
| AES-SIV           | :green_heart:              | :green_heart:       | 2      | [RFC 5297]        |
| AES-GCM-SIV       | :green_heart:              | :green_heart:†      | 2      | Forthcoming‡      |
| AES-GCM           | :green_heart:              | :broken_heart:      | 2      | [NIST SP 800-38D] |
| AES-CCM           | :green_heart:              | :broken_heart:      | 2      | [NIST SP 800-38C] |
| AES-CBC           | :broken_heart:             | :broken_heart:      | 1      | [NIST SP 800-38A] |
| AES-CTR           | :broken_heart:             | :broken_heart:      | 1      | [NIST SP 800-38A] |
| ChaCha20+Poly1305 | :green_heart:              | :broken_heart:      | 2      | [RFC 7539]        |
| XSalsa20+Poly1305 | :green_heart:              | :broken_heart:      | 2      | None              |

† Previous drafts of the AES-GCM-SIV specification were vulnerable to [key recovery attacks].
  These attacks are being addressed in newer drafts of the specification.

‡ Work is underway in the IRTF CFRG to provide an informational RFC for AES-GCM-SIV.
  For more information, see [draft-irtf-cfrg-gcmsiv][AES-GCM-SIV].

When standardization work around [AES-GCM-SIV] is complete, it will be
[seriously considered for inclusion in this library](https://github.com/miscreant/miscreant/issues/31).
**AES-GCM-SIV** has the advantage of the [GHASH] (technically **POLYVAL**)
function being able to run in parallel, versus **AES-CMAC**'s sequential
operation.

**AES-SIV** has the advantages of stronger security guarantees, simplicity,
and that it can be implemented using the AES encryption function alone, making
it a better choice for environments where a hardware accelerated version of the
**GHASH** function is unavailable, such as low-powered mobile devices and
so-called "Internet of Things" embedded use cases.

[Misuse Resistance]: https://www.lvh.io/posts/nonce-misuse-resistance-101.html
[NIST SP 800-38A]: https://dx.doi.org/10.6028/NIST.SP.800-38A
[NIST SP 800-38B]: https://dx.doi.org/10.6028/NIST.SP.800-38B
[NIST SP 800-38C]: https://dx.doi.org/10.6028/NIST.SP.800-38C
[NIST SP 800-38D]: https://dx.doi.org/10.6028/NIST.SP.800-38D
[RFC 7539]: https://tools.ietf.org/html/rfc7539
[key recovery attacks]: https://mailarchive.ietf.org/arch/attach/cfrg/pdfL0pM_N.pdf
[AES-GCM-SIV]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-gcmsiv/
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


## Frequently Asked Questions (FAQ)

### 1. Q: If AES-SIV is so great, why have I never heard of it?

A: Good question! It's an underappreciated gem in cryptography.

### 2. Q: What does "SIV" stand for?

A: SIV stands for "synthetic initialization vector" and refers to the process
of deriving/"synthesizing" the initialization vector (i.e. the starting counter)
for AES-CTR encryption from the given message headers and plaintext message.

Where other schemes might have you randomly generate an IV, SIV modes
pseudorandomly "synthesize" one from the key, plaintext, and additional message
headers including optional associated data and nonce.

### 3. Q: What's the tl;dr for why I should use this?

A: It provides stronger security properties at the cost of a small performance
hit as compared to **AES-GCM**. We hope to have benchmarks soon so we can show
exactly how much performance is lost, however the scheme is still amenable to
full hardware acceleration and should still remain very fast.

The **CHAIN** construction provides the only "streaming" [misuse resistant]
[authenticated encryption] scheme with a rigorous security proof.

The **STREAM** construction provides streaming [authenticated encryption]
and defends against reordering and truncation attacks.

There are other libraries that try to solve this problem, such as [saltpack],
however these libraries do not provide constructions with security proofs,
nor do they provide misuse resistant authenticated encryption. In particular
[saltpack] is a rather complicated amateur construction which does many
repitious and redundant HMAC operations with little justification as to why
or if all relevant data is actually cryptographically bound, much less a
rigorous security proof.

[saltpack]: https://saltpack.org/

### 4. Q: Are there any disadvantages to AES-SIV?

A: Using the AES function as a MAC (i.e. **AES-CMAC**) is more expensive than
faster hardware accelerated functions such as **GHASH** and **POLYVAL** (which
use _CLMUL_ instructions on Intel CPUs). Additionally **AES-CMAC** relies on
chaining and therefore cannot run in parallel. This makes **AES-SIV** slower
than **AES-GCM-SIV** on Intel systems, however **AES-SIV** provides better
security guarantees and will be faster on systems that do not have hardware
acceleration for **GHASH**. We hope to post benchmark numbers soon.

Due to the 128-bit size of the AES block function, **AES-SIV** can only be
safely used to encrypt up to approximately 2<sup>64</sup> messages under the
same key before the "birthday bound" is hit and repeated IVs become probable
enough to be a security concern. Though this number is relatively large, it is
not outside the realm of possibility.

### 5. Q: Are there any disadvantages to the SIV approach in general?

A: SIV encryption requires making a complete pass over the input in order to
calculate the IV. This is less cache efficient than modes which are able
to operate on the plaintext block-by-block, performing encryption and
authentication at the same time. This makes SIV encryption slightly slower
than non-SIV encryption.

However, this does not apply to SIV decryption: since the IV is (allegedly)
known in advance, SIV decryption and authentication can be performed
block-by-block, making it just as fast as the corresponding non-SIV mode
(which for **AES-SIV** would be **AES-EAX** mode).

### 6. Q: Isn't MAC-then-encrypt bad? Shouldn't you use encrypt-then-MAC?

A: Though SIV modes run the MAC operation first, then the encryption function
second, they are a bit different from what is typically referred to as
"MAC-then-encrypt". SIV modes cryptographically bind the encryption and
authentication together by using the authentication tag as an input to the
encryption cipher, making them provably secure for all the same classes of
attacks as encrypt-then-MAC modes.

Another common source of problems with MAC-then-encrypt is padding oracles,
which are commonly seen with CBC modes. **AES-SIV** is based on CTR mode, which
is a stream cipher and therefore doesn't need padding, making it immune to
padding oracles by design.

Authenticating the decrypted data does involve decrypting it, however. This
means decrypted data is, at one point in time, in memory before it is
authenticated. This increases the risk that attacker-controlled plaintext
might wind up being used due to authentication bugs.

These libraries attempt to ensure unauthenticated plaintext is never exposed.
Furthermore some libraries will perform the **AES-CTR** portion of **AES-GCM**
decryption without checking the GCM tag, so encrypt-then-MAC is not a
bulletproof solution to preventing exposure of unauthenticated plaintexts.
To some degree you will always be trusting the implementation quality of a
particular library to ensure it operates in a secure manner.

### 7. Q: Is this algorithm NIST approved / FIPS compliant?

A: **AES-SIV** is the combination of two NIST approved algorithms:
**AES-CTR** encryption as described in [NIST SP 800-38A], and
**AES-CMAC** authentication as described in [NIST SP 800-38B].

However, while **AES-SIV** was [submitted to NIST] as a [proposed mode],
it has never received official approval from NIST.

If you are considering using this software in a FIPS 140-2 environment, please
check with your FIPS auditor before proceeding. It may be possible to justify
the use of **AES-SIV** based on its NIST approved components, but we are not
FIPS auditors and cannot give prescriptive advice here.

[submitted to NIST]: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/siv/siv.pdf
[proposed mode]: http://csrc.nist.gov/groups/ST/toolkit/BCM/modes_development.html

### 8. Q: Are there any patent concerns around AES-SIV mode?

A: No, there are [no IP rights concerns] with **AES-SIV** mode. To the best of
our knowledge, the algorithm is entirely in the public domain. 

[no IP rights concerns]: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/siv/ip.pdf

### 9. Q: Why not wait for the winner of the CAESAR competition to be announced?

A: The [CAESAR] competition (to select a next generation authentication encryption
cipher) seems to be taking much longer than was originally expected. Even when
it concludes, it will be some time before relevant standards are written as to
the usage and deployment of its winner.

Meanwhile [RFC 5297] is nearly a decade old, and **AES-SIV** has seen some
organic usage. While not entirely optimal by the metrics of the CAESAR
competition, it's a boring, uncontroversial solution we can use off-the-shelf today.

[CAESAR]: https://competitions.cr.yp.to/caesar-submissions.html

### 10. Q: Do you plan on supporting additional ciphers? (e.g. AES-GCM-SIV, HS1-SIV, AEZ)

A: Yes, please see this issue on [adding an additional high-performance cipher to Miscreant].

There are some compelling candidates:

* [AES-GCM-SIV] is a high-performance SIV mode currently in the final stages
  of standardization by the IRTF CFRG.
* [AES-PMAC-SIV][AES-PMAC] is an alternatitive construction of **AES-SIV** which
  replaces **AES-CMAC** with [AES-PMAC], a parallelizable MAC built on AES
  designed by [Phil Rogaway].
* [AEZ] is a newer, faster, parallelizable authenticated encryption cipher with
  improved security properties, co-designed by [Phil Rogaway] who also designed
  **AES-SIV**.
* [HS1-SIV] is a authenticated encryption cipher several people thought was
  compelling but was unfortunately eliminated from the [CAESAR] competition.

[adding an additional high-performance cipher to Miscreant]: https://github.com/miscreant/miscreant/issues/31
[AES-PMAC]: http://web.cs.ucdavis.edu/~rogaway/ocb/pmac-bak.htm
[AEZ]: http://web.cs.ucdavis.edu/~rogaway/aez/
[HS1-SIV]: https://competitions.cr.yp.to/round2/hs1sivv2.pdf

### 11. Q: This project mentions security proofs several times. Where do I find them?

A: Please see the paper
[Deterministic Authenticated-Encryption: A Provable-Security Treatment of the Key-Wrap Problem](http://web.cs.ucdavis.edu/~rogaway/papers/keywrap.pdf).

### 12. Q: Where are CHAIN/STREAM? I can't find them!

A: The many claims of support in the READMEs are actually lies! They are not implemented yet.
Support is forthcoming, sorry!

Please see the tracking issues [CHAIN support (OAE2)] and [STREAM support (Nonce-based OAE)]
to follow progress on adding support.

## Copyright

Copyright (c) 2017 [The Miscreant Developers][AUTHORS].
Distributed under the MIT license. See [LICENSE.txt] for further details.

Some language-specific subprojects include sources from other authors with more
specific licensing requirements, though all projects are MIT licensed.
Please see the respective **LICENSE.txt** files in each project for more
information.

[AUTHORS]: https://github.com/miscreant/miscreant/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
