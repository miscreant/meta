require "cmac"
require "openssl"
require "aes_siv/version"

class AES_SIV
  DOUBLE_CONSTANT = ("\x0" * 15) + "\x87"

  def initialize(key)
    raise ArgumentError unless [32, 48, 64].include?(key.length)

    length = key.length / 2

    @key1 = key.slice(0, length)
    @key2 = key.slice(length..-1)
  end

  def encrypt(plaintext, options = {})
    inputs = _gather_inputs(plaintext, options)
    v = _s2v(inputs)
    ciphertext = _transform(v, plaintext)
    v + ciphertext
  end

  def decrypt(ciphertext, options = {})
    v = ciphertext.slice(0, 16)
    ciphertext = ciphertext.slice(16..-1)
    plaintext = _transform(v, ciphertext)

    inputs = _gather_inputs(plaintext, options)
    t = _s2v(inputs)

    if t == v
      plaintext
    else
      fail "bad encrypt"
    end
  end

  def _gather_inputs(plaintext, options = {})
    associated_data = options.fetch(:associated_data, [])
    associated_data = Array(associated_data)
    nonce = options[:nonce]

    inputs = []
    inputs.concat(associated_data)
    inputs << nonce if nonce
    inputs << plaintext
    inputs
  end

  def _transform(v, data)
    counter = v.dup
    counter[8] = (counter[8].ord & 0x7f).chr
    counter[12] = (counter[12].ord & 0x7f).chr

    cipher = OpenSSL::Cipher::AES.new(@key1.length * 8, :CTR)
    cipher.encrypt
    cipher.iv = counter
    cipher.key = @key2
    cipher.update(data) + cipher.final
  end

  def _s2v(inputs)
    inputs = Array(inputs)
    cmac = CMAC.new(@key1)
    if inputs.empty?
      data = ("\0" * 15) + "\x01"
      cmac.sign(data)
    else
      d = cmac.sign("\0" * 16)

      inputs.each_with_index do |input, index|
        break if index == inputs.size - 1

        d = _double(d)
        block = cmac.sign(input)
        d = _xor(d, block)
      end

      input = inputs.last
      if input.bytesize >= 16
        d = _xorend(input, d)
      else
        d = _double(d)
        d = _xor(d, _pad(input))
      end

      cmac.sign(d)
    end
  end

  def _pad(value)
    difference = 15 - value.length
    pad = "\x80".b  + ("\0" * difference)
    value + pad
  end

  def _double(value)
    if value[0].ord < 0x80
      _leftshift(value)
    else
      _xor(_leftshift(value), DOUBLE_CONSTANT)
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

  def _xorend(a, b)
    difference = a.length - b.length
    left = a.slice(0, difference)
    right = a.slice(difference..-1)
    left + _xor(right, b)
  end
end
