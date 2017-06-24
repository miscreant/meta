# CMAC [![Build Status](https://secure.travis-ci.org/jtdowney/cmac.png?branch=master)](https://travis-ci.org/jtdowney/cmac)

This gem is ruby implementation of the Cipher-based Message Authentication Code (CMAC) as defined in [RFC4493](http://tools.ietf.org/html/rfc4493), [RFC4494](http://tools.ietf.org/html/rfc4494), and [RFC4615](http://tools.ietf.org/html/rfc4615). Message authentication codes provide integrity protection of data given that two parties share a secret key.

```ruby
key = OpenSSL::Random.random_bytes(16)
message = 'attack at dawn'
cmac = CMAC.new(key)
cmac.sign(message)
 => "\xF6\xB8\xC1L]s\xBF\x1A\x87<\xA4\xA1Z\xE0f\xAA"
```

Once you've obtained the signature (also called a tag) of a message you can use CMAC to verify it as well.

```ruby
tag = "\xF6\xB8\xC1L]s\xBF\x1A\x87<\xA4\xA1Z\xE0f\xAA"
cmac.valid_message?(tag, message)
 => true
cmac.valid_message?(tag, 'attack at dusk')
 => false
```

CMAC can also be used with a variable length input key as described in RFC4615.

```ruby
key = 'setec astronomy'
message = 'attack at dawn'
cmac = CMAC.new(key)
cmac.sign(message)
 => "\\\x11\x90\xE6\x91\xB2\xC4\x82`\x90\xA6\xEC:\x0E\x1C\xF3"
```
