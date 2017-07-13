# sivchain.go [![Build Status][build-shield]][build-link] [![GoDoc][godoc-shield]][godoc-link] [![Go Report Card][goreport-shield]][goreport-link] [![MIT licensed][license-shield]][license-link]

[build-shield]: https://secure.travis-ci.org/zcred/sivchain.svg?branch=master
[build-link]: http://travis-ci.org/zcred/sivchain
[godoc-shield]: https://godoc.org/github.com/zcred/sivchain/go?status.svg
[godoc-link]: https://godoc.org/github.com/zcred/sivchain/go
[goreport-shield]: https://goreportcard.com/badge/github.com/zcred/sivchain
[goreport-link]: https://goreportcard.com/report/github.com/zcred/sivchain
[license-shield]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/zcred/sivchain/blob/master/LICENSE.txt

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

Go implementation of **SIVChain**: Advanced symmetric encryption using the
[AES-SIV] ([RFC 5297]) and [CHAIN] constructions, providing easy-to-use
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
[CHAIN]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf
[nonce-reuse misuse-resistance]: https://www.lvh.io/posts/nonce-misuse-resistance-101.html
[AES-GCM]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[chosen ciphertext attacks]: https://en.wikipedia.org/wiki/Chosen-ciphertext_attack
[toplevel README.md]: https://github.com/zcred/sivchain/blob/master/README.md

## Help and Discussion

Have questions? Want to suggest a feature or change?

* [Gitter]: web-based chat about zcred projects including **sivchain.go**
* [Google Group]: join via web or email ([zcred+subscribe@googlegroups.com])

[Gitter]: https://gitter.im/zcred/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/zcred
[zcred+subscribe@googlegroups.com]: mailto:zcred+subscribe@googlegroups.com

## Security Notice

**!!! DO NOT USE, NOT TESTED PROPERLY YET !!!**
