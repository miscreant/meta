# sivchain.rb [![Latest Version][gem-shield]][gem-link] [![Build Status][build-image]][build-link] [![Code Climate][codeclimate-image]][codeclimate-link] [![MIT licensed][license-image]][license-link]

[gem-shield]: https://badge.fury.io/rb/sivchain.svg
[gem-link]: https://rubygems.org/gems/sivchain
[build-image]: https://secure.travis-ci.org/zcred/sivchain.svg?branch=master
[build-link]: http://travis-ci.org/zcred/sivchain
[codeclimate-image]: https://codeclimate.com/github/zcred/sivchain/badges/gpa.svg
[codeclimate-link]: https://codeclimate.com/github/zcred/sivchain
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/zcred/sivchain/blob/master/LICENSE.txt

> The best crypto you've never heard of, brought to you by [Phil Rogaway]

Ruby implementation of **SIVChain**: Advanced symmetric encryption using the
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

This library is tested against the following MRI versions:

- 2.2
- 2.3
- 2.4

Other Ruby versions may work, but are not officially supported.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "sivchain"
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install zser

## API

### SIVChain::AES::SIV

The `SIVChain::AES::SIV` class provides the main interface to the **AES-SIV**
misuse resistant authenticated encryption function.

To make a new instance, pass in a 32-byte or 64-byte key. Note that these
options are twice the size of what you might be expecting (AES-SIV uses two
AES keys).

You can generate a random key using the `generate_key` method (default 32 bytes):

```ruby
key = SIVChain::AES::SIV.generate_key
siv = SIVChain::AES::SIV.new(key)
# => #<SIVChain::AES::SIV:0x007fe0109e85e8>
```

#### Encryption (#seal)

The `SIVChain::AES::SIV#seal` method encrypts a message along with a set of
*associated data* message headers.

It's recommended to include a unique "nonce" value with each message. This
prevents those who may be observing your ciphertexts from being able to tell
if you encrypted the same message twice. However, unlike other cryptographic
algorithms where using a nonce has catastrophic security implications such as
key recovery, reusing a nonce with AES-SIV only leaks repeated ciphertexts to
attackers.

Example:

```ruby
message = "Hello, world!"
nonce = SecureRandom.random_bytes(16)
ciphertext = siv.seal(message, nonce)
```

#### Decryption (#open)

The `SIVChain::AES::SIV#open` method decrypts a ciphertext with the given key.

Example:

```ruby
message = "Hello, world!"
nonce = SecureRandom.random_bytes(16)
ciphertext = siv.seal(message, nonce)
plaintext = siv.open(message, nonce)
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/zcred/zser

## Copyright

Copyright (c) 2013-2017 John Downey, [The Zcred Developers][AUTHORS].
See [LICENSE.txt] for further details.

[AUTHORS]: https://github.com/zcred/zcred/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/zcred/sivchain/blob/master/ruby/LICENSE.txt
