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
Advanced symmetric encryption using the [AES-SIV] ([RFC 5297]) and [CHAIN/STREAM]
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
[CHAIN/STREAM]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf
[nonce-reuse misuse-resistance]: https://www.lvh.io/posts/nonce-misuse-resistance-101.html
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

## AEAD API (Use this!)

The Authenticated Encryption with Associated Data API, or `AEAD` API, is the
recommended API for encrypting and decrypting data with Miscreant. It accepts
a nonce, optional associated data (i.e. data you'd like to authenticate along
with the encrypted message), and a message to encrypt.

When decrypting, the same nonce and associated data must be supplied as were
passed at the time of encryption. If anything is amiss, e.g. if the ciphertext
has been tampered with, the cipher will detect it and throw an error.

### miscreant.AEAD.importKey()

The **miscreant.AEAD.importKey()** method creates a new instance of an
**AES-SIV** AEAD encryptor/decryptor.

#### Syntax

```
miscreant.AEAD.importKey(keyData, algorithm[, provider = new miscreant.WebCryptoProvider()])
```

#### Parameters

* **keyData**: a [Uint8Array] containing the encryption key to use.
  Key must be 32-bytes (for AES-128) or 64-bytes (for AES-256), as
  SIV uses two distinct AES keys to perform its operations.
* **algorithm**: a string describing the algorithm to use. The following
  algorithms are supported:
  * `"AES-SIV"`: CMAC-based construction described in [RFC 5297]. Slower but
  standardized and more common.
  * `"AES-PMAC-SIV"`: PMAC-based construction. Supports potentially faster
  implementations, but is non-standard and only available in Miscreant libraries.
* **provider**: a cryptography provider that implements Miscreant's
  [ICryptoProvider] interface.

#### Return Value

The **miscreant.AEAD.importKey()** method returns a [Promise] that, when
fulfilled, returns an `AEAD` encryptor/decryptor.

#### Exceptions

The **miscreant.AEAD.importKey()** method will throw an error if it's
attempting to use the default `window.crypto` provider either doesn't exist
(e.g. `window` is not defined because we're on Node.js) or if that provider
does not provide native implementations of the cryptographic primitives
**AES-SIV** is built on top of.

In these cases, you may choose to use `PolyfillCrypto`, but be aware this may
decrease security.

#### Example

```typescript
import * as miscreant from "miscreant";

let keyData = new Uint32Array(32);

// Assuming window.crypto.getRandomValues is available
window.crypto.getRandomValues(keyData);

let key = await miscreant.AEAD.importKey(keyData, "AES-PMAC-SIV");
```

### seal()

The **seal()** method encrypts a message along with an optional
*associated data* value which will be authenticated along with the message.

#### Syntax

```
key.seal(plaintext, nonce[, associatedData = ""])
```

#### Parameters

* **plaintext**: [Uint8Array] data to be encrypted.
* **nonce**: a single-use value which MUST be unique per encrypted message.
  Can be any length, and use any uniqueness strategy you like, e.g. a counter
  or a cryptographically secure random number generator.
* **associatedData**: (optional) [Uint8Array] that will be *authenticated*
  along with the message (but not encrypted).

#### Return Value

The **seal()** method returns a [Promise] that, when fulfilled, returns a
[Uint8Array] containing the resulting ciphertext.

#### Example

```typescript
import * as miscreant from "miscreant";

let keyData = new Uint8Array(32);

// Assuming window.crypto.getRandomValues is available
window.crypto.getRandomValues(keyData);

let key = await miscreant.SIV.importKey(keyData, "AES-PMAC-SIV");

// Encrypt plaintext

let plaintext = new Uint8Array([2,3,5,7,11,13,17,19,23,29]);
let nonce = new Uint8Array(16);
window.crypto.getRandomValues(nonce);

let ciphertext = await key.seal(plaintext, nonce);
```

### open()

The **open()** method decrypts a message which has been encrypted using
**AES-SIV** or **AES-PMAC-SIV**.

#### Syntax

```
key.open(ciphertext, nonce[, associatedData = ""])
```

#### Parameters

* **ciphertext**: [Uint8Array] containing an encrypted message.
* **nonce**: [Uint8Array] supplied when the message was originally encrypted.
* **associatedData**: (optional) [Uint8Array] supplied when the message was
  originally encrypted.

#### Return Value

The **open()** method returns a [Promise] that, when fulfilled,
returns a [Uint8Array] containing the decrypted plaintext.

#### Exceptions

If the message has been tampered with or is otherwise corrupted, the promise
will be rejected with an **IntegrityError**.

#### Example

```typescript
import * as miscreant from "miscreant";

let keyData = new Uint8Array(32);

// Assuming window.crypto.getRandomValues is available
window.crypto.getRandomValues(keyData);

let key = await miscreant.SIV.importKey(keyData, "AES-PMAC-SIV");

// Encrypt plaintext

let plaintext = new Uint8Array([2,3,5,7,11,13,17,19,23,29]);
let nonce = new Uint8Array(16);
window.crypto.getRandomValues(nonce);

let ciphertext = await key.seal(plaintext, nonce);

// Decrypt ciphertext
var decrypted = await key.open(ciphertext, nonce);
```

## STREAM API

Miscreant implements an interface that permits incremental processing of
encrypted data based on the [STREAM] construction, which is provably secure
against a wide range of attacks including truncation and reordering attacks.

The API is provided in the form of `miscreant.StreamEncryptor` and
`miscreant.StreamDecryptor` classes, which each take a per-***STREAM*** key and
nonce, and from there operate a message-at-a-time on input plaintext/ciphertext
along with optional per-message associated data (i.e. data you'd like to
authenticate along with the encrypted message).

[STREAM]: https://github.com/miscreant/miscreant/wiki/STREAM

### miscreant.StreamEncryptor.importKey()

The **miscreant.StreamEncryptor.importKey()** method creates a new instance of
a **STREAM** encryptor, capable of encrypting a stream of authenticated
messages and ensuring their integrity, ordering, and termination.

#### Syntax

```
miscreant.StreamEncryptor.importKey(keyData, nonceData, algorithm[, provider = new miscreant.WebCryptoProvider()])
```

#### Parameters

* **keyData**: a [Uint8Array] containing the encryption key to use.
  Key must be 32-bytes (for AES-128) or 64-bytes (for AES-256), as
  SIV uses two distinct AES keys to perform its operations.
* **nonceData**: a 64-bit (8-byte) [Uint8Array] which MUST be unique to this
  message stream (for a given key).
* **algorithm**: a string describing the algorithm to use. The following
  algorithms are supported:
  * `"AES-SIV"`: CMAC-based construction described in [RFC 5297]. Slower but
  standardized and more common.
  * `"AES-PMAC-SIV"`: PMAC-based construction. Supports potentially faster
  implementations, but is non-standard and only available in Miscreant libraries.
* **provider**: a cryptography provider that implements Miscreant's
  [ICryptoProvider] interface.

#### Return Value

The **miscreant.StreamEncryptor.importKey()** method returns a [Promise] that, when
fulfilled, returns a `StreamEncryptor` object.

#### Exceptions

The **miscreant.StreamEncryptor.importKey()** method will throw an error if it's
attempting to use the default `window.crypto` provider either doesn't exist
(e.g. `window` is not defined because we're on Node.js) or if that provider
does not provide native implementations of the cryptographic primitives
**AES-SIV** is built on top of.

In these cases, you may choose to use `PolyfillCrypto`, but be aware this may
decrease security.

#### Example

```typescript
import * as miscreant from "miscreant";

let keyData = new Uint32Array(32);
let nonceData = new Uint8Array(8);

// Assuming window.crypto.getRandomValues is available
window.crypto.getRandomValues(keyData);
window.crypto.getRandomValues(nonceData);

let encryptor = await miscreant.StreamEncryptor.importKey(keyData, nonceData, "AES-PMAC-SIV");
```

### seal()

The **seal()** method of `miscreant.StreamEncryptor` encrypts a message, and
also takes  an optional *associated data* value which will be authenticated
along with the message (but not encrypted).

Note that unlike the `AEAD` API, **STREAM** encodes the position of the message
into the message stream, so the order in which `seal()` is called is significant.

#### Syntax

```
encryptor.seal(plaintext, [lastBlock = false[, associatedData = ""]])
```

#### Parameters

* **plaintext**: [Uint8Array] data to be encrypted.
* **lastBlock**: (optional; default: false) is this the last block in the stream?
* **associatedData**: (optional) [Uint8Array] that will be *authenticated*
  along with the message (but not encrypted).

#### Return Value

The **seal()** method returns a [Promise] that, when fulfilled, returns a
[Uint8Array] containing the resulting ciphertext.

#### Example

```typescript
import * as miscreant from "miscreant";

let keyData = new Uint32Array(32);
let nonceData = new Uint8Array(8);

// Assuming window.crypto.getRandomValues is available
window.crypto.getRandomValues(keyData);
window.crypto.getRandomValues(nonceData);

let encryptor = await miscreant.StreamEncryptor.importKey(keyData, nonceData, "AES-PMAC-SIV");

// Encrypt plaintext

let msg1 = new Uint8Array([1,2]);
let msg2 = new Uint8Array([3,4,5]);
let msg3 = new Uint8Array([6,7,8,9]);

let ciphertext1 = await encryptor.seal(msg1);
let ciphertext2 = await encryptor.seal(msg2);
let ciphertext3 = await encryptor.seal(msg3, true);
```

### miscreant.StreamDecryptor.importKey()

The **miscreant.StreamDecryptor.importKey()** method creates a new instance of
a **STREAM** decryptor, capable of decrypting a previously encrypted stream of
authenticated messages and ensuring their integrity, ordering, and termination.

#### Syntax

```
miscreant.StreamDecryptor.importKey(keyData, nonceData, algorithm[, provider = new miscreant.WebCryptoProvider()])
```

#### Parameters

* **keyData**: a [Uint8Array] containing the encryption key to use.
  Key must be 32-bytes (for AES-128) or 64-bytes (for AES-256), as
  SIV uses two distinct AES keys to perform its operations.
* **nonceData**: a 64-bit (8-byte) [Uint8Array] which MUST be unique to this
  message stream (for a given key).
* **algorithm**: a string describing the algorithm to use. The following
  algorithms are supported:
  * `"AES-SIV"`: CMAC-based construction described in [RFC 5297]. Slower but
  standardized and more common.
  * `"AES-PMAC-SIV"`: PMAC-based construction. Supports potentially faster
  implementations, but is non-standard and only available in Miscreant libraries.
* **provider**: a cryptography provider that implements Miscreant's
  [ICryptoProvider] interface.

#### Return Value

The **miscreant.StreamDecryptor.importKey()** method returns a [Promise] that, when
fulfilled, returns a `StreamDecryptor` object.

#### Exceptions

The **miscreant.StreamDecryptor.importKey()** method will throw an error if it's
attempting to use the default `window.crypto` provider either doesn't exist
(e.g. `window` is not defined because we're on Node.js) or if that provider
does not provide native implementations of the cryptographic primitives
**AES-SIV** is built on top of.

In these cases, you may choose to use `PolyfillCrypto`, but be aware this may
decrease security.

#### Example

```typescript
import * as miscreant from "miscreant";

let keyData = new Uint32Array(32);
let nonceData = new Uint8Array(8);

// Assuming window.crypto.getRandomValues is available
window.crypto.getRandomValues(keyData);
window.crypto.getRandomValues(nonceData);

let decryptor = await miscreant.StreamDecryptor.importKey(keyData, nonceData, "AES-PMAC-SIV");
```

### open()

The **open()** method decrypts a stream of messages which has been encrypted
using **AES-SIV** or **AES-PMAC-SIV**.

#### Syntax

```
decryptor.open(ciphertext, [lastBlock = false[, associatedData = ""]])
```

#### Parameters

* **ciphertext**: [Uint8Array] containing an encrypted message.
* **lastBlock**: (optional; default: false) is this the last block in the stream?
* **associatedData**: (optional) [Uint8Array] supplied when the message was
  originally encrypted.

#### Return Value

The **open()** method returns a [Promise] that, when fulfilled,
returns a [Uint8Array] containing the decrypted plaintext.

#### Exceptions

If the message has been tampered with or is otherwise corrupted, the promise
will be rejected with an **IntegrityError**.

#### Example

```typescript
import * as miscreant from "miscreant";

let keyData = new Uint32Array(32);
let nonceData = new Uint8Array(8);

// Assuming window.crypto.getRandomValues is available
window.crypto.getRandomValues(keyData);
window.crypto.getRandomValues(nonceData);

let encryptor = await miscreant.StreamEncryptor.importKey(keyData, nonceData, "AES-PMAC-SIV");

// Encrypt plaintext

let msg1 = new Uint8Array([1,2]);
let msg2 = new Uint8Array([3,4,5]);
let msg3 = new Uint8Array([6,7,8,9]);

let ciphertext1 = await encryptor.seal(msg1);
let ciphertext2 = await encryptor.seal(msg2);
let ciphertext3 = await encryptor.seal(msg3, true);

// Decrypt ciphertext
let decryptor = await miscreant.StreamDecryptor.importKey(keyData, nonceData, "AES-PMAC-SIV");

var decrypted1 = await key.open(ciphertext1);
var decrypted2 = await key.open(ciphertext2);
var decrypted3 = await key.open(ciphertext3, true);
```

## SIV API

The `SIV` API is a power-user API that allows you to make full use of the
multiple header feature the SIV construction provides.

### miscreant.SIV.importKey()

The **miscreant.SIV.importKey()** method creates a new instance of an
**AES-SIV** encryptor/decryptor.

#### Syntax

```
miscreant.SIV.importKey(keyData, algorithm[, provider = new miscreant.WebCryptoProvider()])
```

#### Parameters

* **keyData**: a [Uint8Array] containing the encryption key to use.
  Key must be 32-bytes (for AES-128) or 64-bytes (for AES-256), as
  SIV uses two distinct AES keys to perform its operations.
* **algorithm**: a string describing the algorithm to use. The following
  algorithms are supported:
  * `"AES-SIV"`: CMAC-based construction described in [RFC 5297]. Slower but
  standardized and more common.
  * `"AES-PMAC-SIV"`: PMAC-based construction. Supports potentially faster
  implementations, but is non-standard and only available in Miscreant libraries.
* **provider**: a cryptography provider that implements Miscreant's
  [ICryptoProvider] interface.

#### Return Value

The **miscreant.SIV.importKey()** method returns a [Promise] that, when
fulfilled, returns a SIV encryptor/decryptor.

#### Exceptions

The **miscreant.SIV.importKey()** method will throw an error if it's
attempting to use the default `window.crypto` provider either doesn't exist
(e.g. `window` is not defined because we're on Node.js) or if that provider
does not provide native implementations of the cryptographic primitives
**AES-SIV** is built on top of.

In these cases, you may choose to use `PolyfillCrypto`, but be aware this may
decrease security.

#### Example

```typescript
import * as miscreant from "miscreant";

let keyData = new Uint32Array(32);

// Assuming window.crypto.getRandomValues is available
window.crypto.getRandomValues(keyData);

let key = await miscreant.SIV.importKey(keyData, "AES-PMAC-SIV");
```

### seal()

The **seal()** method encrypts a message along with a set of message headers
known as *associated data*.

#### Syntax

```
key.seal(associatedData, plaintext)
```

#### Parameters

* **associatedData**: array of [Uint8Array] values containing data which won't
  be encrypted, but will be *authenticated* along with the message. This is
  useful for including a *nonce* for the message, ensuring that if the same
  message is encrypted twice, the ciphertext will not repeat.
* **plaintext**: a [Uint8Array] data to be encrypted.

#### Return Value

The **seal()** method returns a [Promise] that, when fulfilled, returns a
[Uint8Array] containing the resulting ciphertext.

#### Example

```typescript
import * as miscreant from "miscreant";

let keyData = new Uint8Array(32);

// Assuming window.crypto.getRandomValues is available
window.crypto.getRandomValues(keyData);

let key = await miscreant.SIV.importKey(keyData, "AES-PMAC-SIV");

// Encrypt plaintext

let plaintext = new Uint8Array([2,3,5,7,11,13,17,19,23,29]);
let nonce = new Uint8Array(16);
window.crypto.getRandomValues(nonce);

let ciphertext = await key.seal(plaintext, [nonce]);
```

### open()

The **open()** method decrypts a message which has been encrypted using
**AES-SIV** or **AES-PMAC-SIV**.

#### Syntax

```
key.open(associatedData, ciphertext)
```

#### Parameters

* **associatedData**: array of [Uint8Array] values supplied as associated data
  when the message was originally encrypted.
* **ciphertext**: a [Uint8Array] containing an encrypted message.

#### Return Value

The **open()** method returns a [Promise] that, when fulfilled,
returns a [Uint8Array] containing the decrypted plaintext.

If the message has been tampered with or is otherwise corrupted, the promise
will be rejected with an **IntegrityError**.

#### Example

```typescript
import * as miscreant from "miscreant";

let keyData = new Uint8Array(32);

// Assuming window.crypto.getRandomValues is available
window.crypto.getRandomValues(keyData);

let key = await SIV.importKey(keyData, "AES-PMAC-SIV");

// Encrypt plaintext

let plaintext = new Uint8Array([2,3,5,7,11,13,17,19,23,29]);
let nonce = new Uint8Array(16);
window.crypto.getRandomValues(nonce);

let ciphertext = await key.seal(plaintext, [nonce]);

// Decrypt ciphertext
var decrypted = await key.open(ciphertext, [nonce]);
```

[Promise]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise
[Uint8Array]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array
[Crypto]: https://developer.mozilla.org/en-US/docs/Web/API/Crypto

## Polyfill Support

**WARNING:** The polyfill implementation is not constant time! Please read
the [Polyfill Security Warning](#polyfill-security-warning) before proceeding!

By default, this library uses a WebCrypto-based implementation of **AES-SIV** and
will throw an exception if WebCrypto is unavailable.

However, this library also contains a `PolyfillCrypto` implementation which
can be passed as the second parameter to `SIV.importKey()`. This implementation
uses pure JavaScript, however is not provided by default because there are
security concerns around its implementation.

This implementation should only be used in environments which have no support
for WebCrypto whatsoever. WebCrypto should be available on most modern browsers.
On Node.js, we would suggest you consider [node-webcrypto-ossl] before using
the polyfill implementations, although please see that project's security
warning before using it.

If you have already read the [Polyfill Security Warning](#polyfill-security-warning),
understand the security concerns, and would like to use it anyway, create a
`PolyfillCryptoProvider` instance and pass it into a constructor:

```typescript
const key = miscreant.AEAD.importKey(keyData, "AES-PMAC-SIV", new miscreant.PolyfillCryptoProvider());
```

## Code of Conduct

We abide by the [Contributor Covenant][cc] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md].

[cc]: https://contributor-covenant.org
[CODE_OF_CONDUCT.md]: https://github.com/miscreant/miscreant/blob/master/CODE_OF_CONDUCT.md

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/miscreant/miscreant

## Copyright

Copyright (c) 2017 [The Miscreant Developers][AUTHORS].

AES polyfill implementation derived from the Go standard library:
Copyright (c) 2012 The Go Authors. All rights reserved.

See [LICENSE.txt] for further details.

[AUTHORS]: https://github.com/miscreant/miscreant/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/miscreant/miscreant/blob/master/js/LICENSE.txt
