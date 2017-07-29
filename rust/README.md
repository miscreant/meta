# miscreant.rs [![crate][crate-image]][crate-link] [![Build Status][build-image]][build-link] [![MIT licensed][license-image]][license-link] [![Gitter Chat][gitter-image]][gitter-link]

[crate-shield]: https://img.shields.io/crates/v/miscreant.svg
[crate-link]: https://crates.io/crates/miscreant
[build-image]: https://secure.travis-ci.org/miscreant/miscreant.svg?branch=master
[build-link]: http://travis-ci.org/miscreant/miscreant
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
[gitter-image]: https://badges.gitter.im/badge.svg
[gitter-link]: https://gitter.im/miscreant/Lobby

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

Rust implementation of **Miscreant**: Advanced symmetric encryption using the
AES-SIV ([RFC 5297]) and [CHAIN/STREAM] constructions, providing easy-to-use (or
rather, hard-to-misuse) encryption of individual messages or message streams.

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

* [Gitter]: web-based chat about miscreant projects including **miscreant.rb**
* [Google Group]: join via web or email ([miscreant-crypto+subscribe@googlegroups.com])

[Gitter]: https://gitter.im/miscreant/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/miscreant-crypto
[miscreant-crypto+subscribe@googlegroups.com]: mailto:miscreant-crypto+subscribe@googlegroups.com?subject=subscribe

## Security Notice

Though this library is written by cryptographic professionals, it has not
undergone a thorough security audit, and cryptographic professionals are still
humans that make mistakes. Use this library at your own risk.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/miscreant/miscreant

## Copyright

Copyright (c) 2017 [The Miscreant Developers][AUTHORS].
See [LICENSE.txt] for further details.

[AUTHORS]: https://github.com/miscreant/miscreant/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
