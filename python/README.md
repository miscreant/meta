# sivchain.py [![Latest Version][pypi-shield]][pypi-link] [![Build Status][build-image]][build-link] [![MIT licensed][license-image]][license-link]

[pypi-shield]: https://img.shields.io/pypi/v/sivchain.svg
[pypi-link]: https://pypi.python.org/pypi/sivchain/
[build-image]: https://secure.travis-ci.org/zcred/sivchain.svg?branch=master
[build-link]: http://travis-ci.org/zcred/sivchain
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/zcred/sivchain/blob/master/LICENSE.txt

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

Python implementation of **SIVChain**: Advanced symmetric encryption using the
AES-SIV ([RFC 5297]) and [CHAIN] constructions, providing easy-to-use (or
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
[CHAIN]: http://web.cs.ucdavis.edu/~rogaway/papers/oae.pdf
[nonce-reuse misuse-resistance]: https://www.lvh.io/posts/nonce-misuse-resistance-101.html
[AES-GCM]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[chosen ciphertext attacks]: https://en.wikipedia.org/wiki/Chosen-ciphertext_attack
[toplevel README.md]: https://github.com/zcred/sivchain/blob/master/README.md

## Help and Discussion

Have questions? Want to suggest a feature or change?

* [Gitter]: web-based chat about zcred projects including **sivchain.rb**
* [Google Group]: join via web or email ([zcred+subscribe@googlegroups.com])

[Gitter]: https://gitter.im/zcred/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/zcred
[zcred+subscribe@googlegroups.com]: mailto:zcred+subscribe@googlegroups.com

## Security Notice

Though this library is written by cryptographic professionals, it has not
undergone a thorough security audit, and cryptographic professionals are still
humans that make mistakes. Use this library at your own risk.

## Requirements

This library is tested on Python 2.7 and 3.6.

It depends on the Python `cryptography` library. For more information on
installing this library, please see:

https://cryptography.io/en/latest/installation/

## Installation

Install **SIVChain** with pip using:

```
$ pip install sivchain
```

## API

Import the `SIV` class from `sivchain.aes.siv` using:

```python
from sivchain.aes.siv import SIV
```

The `SIV` class provides the main interface to the **AES-SIV** misuse resistant
authenticated encryption function.

To make a new instance, pass in a 32-byte or 64-byte key. Note that these
options are twice the size of what you might be expecting (AES-SIV uses two
AES keys).

You can generate a random key using the `generate_key` method (default 32 bytes):

```python
key = SIV.generate_key()
siv = SIV.new(key)
```

#### Encryption (seal)

The `seal` method encrypts a message along with a set of *associated data*
which acts as message headers.

It's recommended to include a unique "nonce" value with each message. This
prevents those who may be observing your ciphertexts from being able to tell
if you encrypted the same message twice. However, unlike other cryptographic
algorithms where using a nonce has catastrophic security implications such as
key recovery, reusing a nonce with AES-SIV only leaks repeated ciphertexts to
attackers.

Example:

```python
import os
from sivchain.aes.siv import SIV

key = SIV.generate_key()
siv = SIV.new(key)

message = "Hello, world!"
nonce = os.urandom(16)
ciphertext = siv.seal(message, [nonce])
```

#### Decryption (open)

The `open` method decrypts a ciphertext with the given key.

Example:

```python
import os
from sivchain.aes.siv import SIV

key = SIV.generate_key()
siv = SIV.new(key)

message = "Hello, world!"
nonce = os.urandom(16)

ciphertext = siv.seal(message, [nonce])
plaintext = siv.open(message, [nonce])
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/zcred/zser

## Copyright

Copyright (c) 2017 [The Zcred Developers][AUTHORS].
See [LICENSE.txt] for further details.

[AUTHORS]: https://github.com/zcred/zcred/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/zcred/sivchain/blob/master/LICENSE.txt
