# frozen_string_literal: true

module SIVChain
  # The AES-CMAC message authentication code
  class CMAC
    Exception = Class.new(StandardError)
    ZeroBlock = ("\0" * 16).b.freeze
    ConstantBlock = (("\0" * 15) + "\x87").b.freeze

    def initialize(key)
      case key.length
      when 16
        @cipher = OpenSSL::Cipher.new("AES-128-ECB")
      when 32
        @cipher = OpenSSL::Cipher.new("AES-256-ECB")
      else raise ArgumentError, "key must be 16 or 32 bytes"
      end

      @cipher.encrypt
      @cipher.padding = 0
      @cipher.key = key
      @key1, @key2 = _generate_subkeys
    end

    alias inspect to_s

    def digest(message)
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
        block = _xor(final_block, block) if i == range.last
        block = _xor(block, last_ciphertext)
        last_ciphertext = _encrypt_block(block)
      end

      last_ciphertext
    end

    private

    def _encrypt_block(block)
      @cipher.update(block) + @cipher.final
    end

    def _generate_subkeys
      key0 = _encrypt_block(ZeroBlock)
      key1 = _next_key(key0)
      key2 = _next_key(key1)
      [key1, key2]
    end

    def _needs_padding?(message)
      message.empty? || message.length % 16 != 0
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
      words = input.unpack("N4").reverse
      words = words.map do |word|
        new_word = (word << 1) & 0xFFFFFFFF
        new_word |= overflow
        overflow = (word & 0x80000000) >= 0x80000000 ? 1 : 0
        new_word
      end
      words.reverse.pack("N4")
    end

    def _pad_message(message)
      padded_length = message.length + 16 - (message.length % 16)
      message += "\x80".b
      message.ljust(padded_length, "\0")
    end

    def _xor(a, b)
      a = a.b
      b = b.b

      output = "".b
      length = [a.length, b.length].min
      length.times do |i|
        output << (a[i].ord ^ b[i].ord).chr
      end

      output
    end
  end
end
