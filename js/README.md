# sivchain.js [![Latest Version][npm-shield]][npm-link] [![Build Status][build-image]][build-link] [![MIT licensed][license-image]][license-link]

[npm-shield]: https://img.shields.io/npm/v/sivchain.svg
[npm-link]: https://www.npmjs.com/package/sivchain
[build-image]: https://secure.travis-ci.org/zcred/sivchain.svg?branch=master
[build-link]: http://travis-ci.org/zcred/sivchain
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/zcred/sivchain/blob/master/LICENSE.txt

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

JavaScript-compatible TypeScript implementation of **SIVChain**:
Advanced symmetric encryption using the AES-SIV ([RFC 5297]) and [CHAIN]
constructions, providing easy-to-use (or rather, hard-to-misuse) encryption of
individual messages or message streams.

For more information, see the [toplevel README.md].

[Phil Rogaway]: https://en.wikipedia.org/wiki/Phillip_Rogaway
[RFC 5297]: https://tools.ietf.org/html/rfc5297
[CHAIN]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf
[toplevel README.md]: https://github.com/zcred/sivchain/blob/master/README.md

## Help and Discussion

Have questions? Want to suggest a feature or change?

* [Gitter]: web-based chat about zcred projects including **sivchain.js**
* [Google Group]: join via web or email ([zcred+subscribe@googlegroups.com])

[Gitter]: https://gitter.im/zcred/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/zcred
[zcred+subscribe@googlegroups.com]: mailto:zcred+subscribe@googlegroups.com

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

The **SIV.importKey()** method creates a new instance of an AES-SIV
encryptor/decryptor.

#### Syntax

```
SIV.importKey(keyData, algorithm)
```

#### Parameters

* **keyData**: a [Uint8Array] containing the encryption key to use.
  Key must be 32-bytes (for AES-128) or 64-bytes (for AES-256), as
  SIV uses two distinct AES keys to perform its operations.
* **algorithm**: a string describing the algorithm to use. The only algorithm
  presently supported is `"AES-SIV"`.

#### Return Value

The **SIV.importKey()** method returns a [Promise] that, when fulfilled,
returns a SIV encryptor/decryptor.

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

The **SIV.open()** method decrypts a message which has been encrypted using AES-SIV.

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
will be rejected with a **IntegrityError**.

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

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/zcred/sivchain

## Copyright

Copyright (c) 2017 Dmitry Chestnykh, [The Zcred Developers][AUTHORS].
See [LICENSE.txt] for further details.

[AUTHORS]: https://github.com/zcred/zcred/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/zcred/zser/blob/master/LICENSE.txt
