# miscreant.js [![Latest Version][npm-shield]][npm-link] [![Build Status][build-image]][build-link] [![Known Vulnerabilities][snyk-image]][snyk-link] [![MIT licensed][license-image]][license-link] [![Gitter Chat][gitter-image]][gitter-link]

[npm-shield]: https://img.shields.io/npm/v/miscreant.svg
[npm-link]: https://www.npmjs.com/package/miscreant
[build-image]: https://secure.travis-ci.org/miscreant/miscreant.svg?branch=master
[build-link]: http://travis-ci.org/miscreant/miscreant
[snyk-image]: https://snyk.io/test/github/miscreant/miscreant/badge.svg?targetFile=js%2Fpackage.json
[snyk-link]: https://snyk.io/test/github/miscreant/miscreant?targetFile=js%2Fpackage.json
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
[gitter-image]: https://badges.gitter.im/badge.svg
[gitter-link]: https://gitter.im/miscreant/Lobby

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

JavaScript-compatible TypeScript implementation of **Miscreant**:
Advanced symmetric encryption library which provides the [AES-SIV] ([RFC 5297]),
[AES-PMAC-SIV], and [STREAM] constructions. These algorithms are easy-to-use
(or rather, hard-to-misuse) and support encryption of individual messages or
message streams.

[AES-SIV]: https://github.com/miscreant/miscreant/wiki/AES-SIV
[RFC 5297]: https://tools.ietf.org/html/rfc5297
[AES-PMAC-SIV]: https://github.com/miscreant/miscreant/wiki/AES-PMAC-SIV
[STREAM]: https://github.com/miscreant/miscreant/wiki/STREAM

**AES-SIV** provides [nonce-reuse misuse-resistance] (NRMR): accidentally
reusing a nonce with this construction is not a security catastrophe,
unlike it is with more popular AES encryption modes like [AES-GCM].
With **AES-SIV**, the worst outcome of reusing a nonce is an attacker
can see you've sent the same plaintext twice, as opposed to almost all other
AES modes where it can facilitate [chosen ciphertext attacks] and/or
full plaintext recovery.

For more information, see the [toplevel README.md].

[nonce-reuse misuse-resistance]: https://github.com/miscreant/miscreant/wiki/Nonce-Reuse-Misuse-Resistance
[AES-GCM]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[chosen ciphertext attacks]: https://en.wikipedia.org/wiki/Chosen-ciphertext_attack
[toplevel README.md]: https://github.com/miscreant/miscreant/blob/master/README.md

## Help and Discussion

Have questions? Want to suggest a feature or change?

* [Gitter]: web-based chat about miscreant projects including **miscreant.js**
* [Google Group]: join via web or email ([miscreant-crypto+subscribe@googlegroups.com])

[Gitter]: https://gitter.im/miscreant/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/miscreant-crypto
[miscreant-crypto+subscribe@googlegroups.com]: mailto:miscreant-crypto+subscribe@googlegroups.com?subject=subscribe

## Security Notice

Though this library is written by cryptographic professionals, it has not
undergone a thorough security audit, and cryptographic professionals are still
humans that make mistakes. Use this library at your own risk.

This library contains two implementations of the cryptographic primitives
which underlie its implementation: ones based on the [Web Cryptography API],
(a.k.a. Web Crypto) and a set of pure JavaScript polyfills.

By default only the Web Crypto versions will be used, and an exception raised
if Web Crypto is not available. Users of this library may opt into using the
polyfills in environments where Web Crypto is unavailable, but see the security
notes below and understand the potential risks before doing so.

### Web Crypto Security Notes

The Web Crypto API should provide access to high-quality implementations of
the underlying cryptographic primitive functions used by this library in
most modern browsers, implemented in optimized native code.

On Node.js, you will need a native WebCrypto provider such as
[node-webcrypto-ossl] to utilize native code implementations of the underlying
ciphers instead of the polyfills. However, please see the security warning
on this package before using it.

[node-webcrypto-ossl]: https://github.com/PeculiarVentures/node-webcrypto-ossl

### Polyfill Security Warning

The AES polyfill implementation (off by default, see above) uses table lookups
and is therefore not constant time. This means there's potential that
co-tenant or even remote attackers may be able to measure minute timing
variations and use them to recover AES keys.

If at all possible, use the Web Crypto implementation instead of the polyfills.

[Web Cryptography API]: https://www.w3.org/TR/WebCryptoAPI/

## Installation

Via [npm](https://www.npmjs.com/):

```bash
npm install miscreant
```

Via [Yarn](https://yarnpkg.com/):

```bash
yarn install miscreant
```

Import Miscreant into your project with:

```js
import * as miscreant from "miscreant";
```

## Documentation

[Please see the Miscreant Wiki](https://github.com/miscreant/miscreant/wiki/JavaScript-Documentation)
for API documentation.

## Code of Conduct

We abide by the [Contributor Covenant][cc] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md].

[cc]: https://contributor-covenant.org
[CODE_OF_CONDUCT.md]: https://github.com/miscreant/miscreant/blob/master/CODE_OF_CONDUCT.md

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/miscreant/miscreant

## Copyright

Copyright (c) 2017-2018 [The Miscreant Developers][AUTHORS].

AES polyfill implementation derived from the Go standard library:
Copyright (c) 2012 The Go Authors. All rights reserved.

See [LICENSE.txt] for further details.

[AUTHORS]: https://github.com/miscreant/miscreant/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/miscreant/miscreant/blob/master/js/LICENSE.txt
