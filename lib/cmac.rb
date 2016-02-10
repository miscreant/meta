require 'openssl'

require 'cmac/version'

class CMAC
  Exception = Class.new(StandardError)
  ZeroBlock = "\0" * 16
  ConstantBlock = ("\0" * 15) + "\x87"

  def initialize(key)
    @key = _derive_key(key.b)
    @key1, @key2 = _generate_subkeys(@key)
  end

  def inspect
    "#<CMAC:0x#{object_id.to_s(16)}>"
  end

  def sign(message, truncate = 16)
    raise CMAC::Exception.new('Tag cannot be greater than maximum (16 bytes)') if truncate > 16
    raise CMAC::Exception.new('Tag cannot be less than minimum (8 bytes)') if truncate < 8

    message = message.b

    if _needs_padding?(message)
      message = _pad_message(message)
      final_block = @key2
    else
      final_block = @key1
    end

    last_ciphertext = ZeroBlock
    count = message.length / 16
    range = Range.new(0, count - 1)
    blocks = range.map { |i| message.slice(16 * i, 16) }
    blocks.each_with_index do |block, i|
      if i == range.last
        block = _xor(final_block, block)
      end

      block = _xor(block, last_ciphertext)
      last_ciphertext = _encrypt_block(@key, block)
    end

    last_ciphertext.slice(0, truncate)
  end
  alias :encrypt :sign

  def valid_message?(tag, message)
    other_tag = sign(message)
    _secure_compare?(tag, other_tag)
  end

  def _derive_key(key)
    if key.length == 16
      key
    else
      cmac = CMAC.new(ZeroBlock)
      cmac.encrypt(key)
    end
  end

  def _encrypt_block(key, block)
    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.encrypt
    cipher.padding = 0
    cipher.key = key
    cipher.update(block) + cipher.final
  end

  def _generate_subkeys(key)
    key0 = _encrypt_block(key, ZeroBlock)
    key1 = _next_key(key0)
    key2 = _next_key(key1)
    [key1, key2]
  end

  def _needs_padding?(message)
    message.length == 0 || message.length % 16 != 0
  end

  def _next_key(key)
    if key[0].ord < 0x80
      _leftshift(key)
    else
      _xor(_leftshift(key), ConstantBlock)
    end
  end

  def _leftshift(input)
    overflow = 0
    words = input.unpack('N4').reverse
    words = words.map do |word|
      new_word = (word << 1) & 0xFFFFFFFF
      new_word |= overflow
      overflow = (word & 0x80000000) >= 0x80000000 ? 1 : 0
      new_word
    end
    words.reverse.pack('N4')
  end

  def _pad_message(message)
    padded_length = message.length + 16 - (message.length % 16)
    message = message + "\x80".b
    message.ljust(padded_length, "\0")
  end

  def _secure_compare?(a, b)
    return false unless a.bytesize == b.bytesize

    bytes = a.unpack("C#{a.bytesize}")

    result = 0
    b.each_byte do |byte|
      result |= byte ^ bytes.shift
    end
    result == 0
  end

  def _xor(a, b)
    a = a.b
    b = b.b

    output = ''
    length = [a.length, b.length].min
    length.times do |i|
      output << (a[i].ord ^ b[i].ord).chr
    end
    output
  end
end
