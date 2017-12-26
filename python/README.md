# miscreant.py [![Latest Version][pypi-shield]][pypi-link] [![Build Status][build-image]][build-link] [![MIT licensed][license-image]][license-link] [![Gitter Chat][gitter-image]][gitter-link]

[pypi-shield]: https://img.shields.io/pypi/v/miscreant.svg
[pypi-link]: https://pypi.python.org/pypi/miscreant/
[build-image]: https://secure.travis-ci.org/miscreant/miscreant.svg?branch=master
[build-link]: http://travis-ci.org/miscreant/miscreant
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
[gitter-image]: https://badges.gitter.im/badge.svg
[gitter-link]: https://gitter.im/miscreant/Lobby

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

[Phil Rogaway]: https://en.wikipedia.org/wiki/Phillip_Rogaway

Python implementation of **Miscreant**: Advanced symmetric encryption library
which provides the [AES-SIV] ([RFC 5297]), [AES-PMAC-SIV], and [STREAM]
constructions. These algorithms are easy-to-use (or rather, hard-to-misuse)
and support encryption of individual messages or message streams.

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

* [Gitter]: web-based chat about miscreant projects including **miscreant.py**
* [Google Group]: join via web or email ([miscreant-crypto+subscribe@googlegroups.com])

[Gitter]: https://gitter.im/miscreant/Lobby
[Google Group]: https://groups.google.com/forum/#!forum/miscreant-crypto
[miscreant-crypto+subscribe@googlegroups.com]: mailto:miscreant-crypto+subscribe@googlegroups.com?subject=subscribe

## Security Notice

This library implements some portions of the construction in pure Python and
therefore these parts are not constant time: though the core cryptography is
provided by the Python `cryptography` library including the AES function,
various other parts, particularly the `s2v` and `dbl` functions are Python.

These functions act on Python integers, which are boxed. They may reveal
timing information which may help an attacker compromise this implementation,
possibly even facilitating complete plaintext recovery. The exact extent to
which this is possible has not been thoroughly investigated, nor has this
library been professionally audited by cryptography experts.

Use this library at your own risk.

## Requirements

This library is tested on Python 2.7 and 3.6.

It depends on the Python `cryptography` library. For more information on
installing this library, please see:

https://cryptography.io/en/latest/installation/

## Installation

Install **Miscreant** with pip using:

```
$ pip install miscreant
```

## API

Import the `SIV` class from `miscreant.aes.siv` using:

```python
from miscreant.aes.siv import SIV
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
from miscreant.aes.siv import SIV

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
from miscreant.aes.siv import SIV

key = SIV.generate_key()
siv = SIV.new(key)

message = "Hello, world!"
nonce = os.urandom(16)

ciphertext = siv.seal(message, [nonce])
plaintext = siv.open(message, [nonce])
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
See [LICENSE.txt] for further details.

[AUTHORS]: https://github.com/miscreant/miscreant/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/miscreant/miscreant/blob/master/LICENSE.txt
