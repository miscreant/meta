# encoding: binary
# frozen_string_literal: true

module SIVChain
  # The Advanced Encryption Standard Block Cipher
  module AES
    # The AES-SIV misuse resistant authenticated encryption cipher
    class SIV
      def initialize(key)
        raise TypeError, "expected String, got #{key.class}" unless key.is_a?(String)
        raise ArgumentError, "key must be Encoding::BINARY" unless key.encoding == Encoding::BINARY
        raise ArgumentError, "key must be 32 or 64 bytes" unless [32, 64].include?(key.length)

        length = key.length / 2

        @key1 = key.slice(0, length)
        @key2 = key.slice(length..-1)
      end

      alias inspect to_s

      def encrypt(plaintext, associated_data = [])
        inputs = []
        inputs.concat(Array(associated_data))
        inputs << plaintext

        v = _s2v(inputs)
        ciphertext = _transform(v, plaintext)
        v + ciphertext
      end

      def decrypt(ciphertext, associated_data = [])
        v = ciphertext.slice(0, 16)
        ciphertext = ciphertext.slice(16..-1)
        plaintext = _transform(v, ciphertext)

        inputs = []
        inputs.concat(Array(associated_data))
        inputs << plaintext
        t = _s2v(inputs)

        raise "bad encrypt" unless Util.ct_equal(t, v)

        plaintext
      end

      private

      def _pad(value)
        difference = 15 - value.length
        pad = "\x80" + ("\0" * difference)
        value + pad
      end

      def _transform(v, data)
        return "".b if data.empty?

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
          return cmac.digest(data)
        end

        d = cmac.digest("\0" * 16)

        inputs.each_with_index do |input, index|
          break if index == inputs.size - 1

          d = Util.double(d)
          block = cmac.digest(input)
          d = Util.xor(d, block)
        end

        input = inputs.last

        if input.bytesize >= 16
          d = _xorend(input, d)
        else
          d = Util.double(d)
          d = Util.xor(d, _pad(input))
        end

        cmac.digest(d)
      end

      def _xorend(a, b)
        difference = a.length - b.length
        left = a.slice(0, difference)
        right = a.slice(difference..-1)
        left + Util.xor(right, b)
      end
    end
  end
end
