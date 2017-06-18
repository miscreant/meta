# sivchain.js [![Latest Version][npm-shield]][npm-link] [![Build Status][build-image]][build-link] [![Known Vulnerabilities][snyk-image]][snyk-link] [![MIT licensed][license-image]][license-link]

[npm-shield]: https://img.shields.io/npm/v/sivchain.svg
[npm-link]: https://www.npmjs.com/package/sivchain
[build-image]: https://secure.travis-ci.org/zcred/sivchain.svg?branch=master
[build-link]: http://travis-ci.org/zcred/sivchain
[snyk-image]: https://snyk.io/test/github/zcred/sivchain/badge.svg?targetFile=js%2Fpackage.json
[snyk-link]: https://snyk.io/test/github/zcred/sivchain?targetFile=js%2Fpackage.json
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/zcred/sivchain/blob/master/LICENSE.txt

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

JavaScript-compatible TypeScript implementation of **SIVChain**:
Advanced symmetric encryption using the [AES-SIV] ([RFC 5297]) and [CHAIN]
constructions, providing easy-to-use (or rather, hard-to-misuse) encryption of
individual messages or message streams.

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

* [Gitter]: web-based chat about zcred projects including **sivchain.js**
* [Google Group]: join via web or email ([zcred+subscribe@googlegroups.com])

[Gitter]: https://gitter.im/zcred/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/zcred
[zcred+subscribe@googlegroups.com]: mailto:zcred+subscribe@googlegroups.com

## Security Notice

This library attempts to use the WebCrypto API when available, however it
falls back on polyfills (i.e. pure JavaScript implementations) in the event
the necessary WebCrypto primitives are not available.

Presently there are no environments that support the full set of algorithms
needed to rely on WebCrypto exclusively (AES-CMAC in particular is not
supported in any environments). Therefore, all environments are relying on
the polyfill implementation to implement part of the AES-SIV algorithm.

The AES polyfill implementation uses table lookups and is therefore not
constant time. This means there's potential that co-tenant or even remote
attackers may be able to measure minute timing variations and use them
to recover the AES key. The exact extent to which this is possible in
practice has not yet been investigated.

Though this library is written by cryptographic professionals, it has not
undergone a thorough security audit, and cryptographic professionals are still
humans that make mistakes. Use this library at your own risk.

All of that said, there are many, many bad cryptography libraries in the
JavaScript ecosystem. This one should hopefully be better than most.

## Installation

Via [npm](https://www.npmjs.com/):

```bash
npm install sivchain
```

Via [Yarn](https://yarnpkg.com/):

```bash
yarn install sivchain
```

Import **sivchain.js** into your project with:

```js
var SIV = require("sivchain");
```

## API

### SIV.importKey()

The **SIV.importKey()** method creates a new instance of an **AES-SIV**
encryptor/decryptor.

#### Syntax

```
SIV.importKey(keyData, algorithm[, crypto = window.crypto])
```

#### Parameters

* **keyData**: a [Uint8Array] containing the encryption key to use.
  Key must be 32-bytes (for AES-128) or 64-bytes (for AES-256), as
  SIV uses two distinct AES keys to perform its operations.
* **algorithm**: a string describing the algorithm to use. The only algorithm
  presently supported is `"AES-SIV"`.
* **crypto**: a cryptography provider that implements the WebCrypto API's
  [Crypto] interface. If `null` is explicitly passed, pure JavaScript polyfills
  will be substituted for native cryptography.

On Node.js, consider using a native WebCrypto provider such as
[node-webcrypto-ossl](https://github.com/PeculiarVentures/node-webcrypto-ossl)
as an alternative to the JavaScript crypto polyfills.

#### Return Value

The **SIV.importKey()** method returns a [Promise] that, when fulfilled,
returns a SIV encryptor/decryptor.

#### Exceptions

The **SIV.importKey()** method will throw an error if it's attempting to use
the default `window.crypto` provider either doesn't exist (e.g. `window` is
not defined because we're on Node.js) or if that provider does not provide
native implementations of the cryptographic primitives **AES-SIV** is built
on top of.

In these cases, pass `null` as the parameter to opt into a fully polyfill
implementation. Be aware this may decrease security.

#### Example

```
// Assuming window.crypto.getRandomValues is available

let key = new Uint32Array(32);
window.crypto.getRandomValues(key);

let siv = await SIV.importKey(key, "AES-SIV");
```

### SIV.seal()

The **SIV.seal()** method encrypts a set of *associated data* message
headers along with a message.

#### Syntax

```
sivObj.seal(associatedData, plaintext)
```

#### Parameters

* **associatedData**: array of [Uint8Array] values containing data which won't
  be encrypted, but will be *authenticated* along with the message. This is
  useful for including a *nonce* for the message, ensuring that if the same
  message is encrypted twice, the ciphertext will not repeat.
* **plaintext**: a [Uint8Array] of data to be encrypted.

#### Return Value

The **SIV.seal()** method returns a [Promise] that, when fulfilled,
returns a [Uint8Array] containing the resulting ciphertext.

#### Example

```
// Assuming window.crypto.getRandomValues is available

let key = new Uint8Array(32);
window.crypto.getRandomValues(key);

let siv = await SIV.importKey(key, "AES-SIV");

// Encrypt plaintext

let plaintext = new Uint8Array([2,3,5,7,11,13,17,19,23,29]);
let nonce = new Uint8Array(16);
window.crypto.getRandomValues(nonce);

let ciphertext = await siv.seal([nonce], plaintext);
```

### SIV.open()

The **SIV.open()** method decrypts a message which has been encrypted using **AES-SIV**.

#### Syntax

```
sivObj.open(associatedData, ciphertext)
```

#### Parameters

* **associatedData**: array of [Uint8Array] values supplied as associated data
  when the message was originally encrypted.
* **ciphertext**: a [Uint8Array] containing an encrypted message.

#### Return Value

The **SIV.open()** method returns a [Promise] that, when fulfilled,
returns a [Uint8Array] containing the decrypted plaintext.

If the message has been tampered with or is otherwise corrupted, the promise
will be rejected with an **IntegrityError**.

#### Example

```
// Assuming window.crypto.getRandomValues is available

let key = new Uint8Array(32);
window.crypto.getRandomValues(key);

let siv = await SIV.importKey(key, "AES-SIV");

// Encrypt plaintext

let plaintext = new Uint8Array([2,3,5,7,11,13,17,19,23,29]);
let nonce = new Uint8Array(16);
window.crypto.getRandomValues(nonce);

let ciphertext = await siv.seal([nonce], plaintext);

// Decrypt ciphertext
var decrypted = await siv.open([nonce], ciphertext);
```

[Promise]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise
[Uint8Array]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array
[Crypto]: https://developer.mozilla.org/en-US/docs/Web/API/Crypto

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/zcred/sivchain

## Copyright

Copyright (c) 2017 Dmitry Chestnykh, [The Zcred Developers][AUTHORS].
See [LICENSE.txt] for further details.

[AUTHORS]: https://github.com/zcred/zcred/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/zcred/sivchain/blob/master/js/LICENSE.txt
