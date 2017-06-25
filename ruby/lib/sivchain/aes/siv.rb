# encoding: binary
# frozen_string_literal: true

module SIVChain
  module AES
    # The AES-SIV misuse resistant authenticated encryption cipher
    class SIV
      # Generate a new random AES-SIV key of the given size
      #
      # @param size [Integer] size of key in bytes (32 or 64)
      #
      # @return [String] newly generated AES-SIV key
      def self.generate_key(size = 32)
        raise ArgumentError, "key size must be 32 or 64 bytes" unless [32, 64].include?(size)
        SecureRandom.random_bytes(size)
      end

      def initialize(key)
        raise TypeError, "expected String, got #{key.class}" unless key.is_a?(String)
        raise ArgumentError, "key must be Encoding::BINARY" unless key.encoding == Encoding::BINARY
        raise ArgumentError, "key must be 32 or 64 bytes" unless [32, 64].include?(key.length)

        length = key.length / 2

        @key1 = key.slice(0, length)
        @key2 = key.slice(length..-1)
      end

      def inspect
        to_s
      end

      def seal(plaintext, associated_data = [])
        v = _s2v(plaintext, associated_data)
        ciphertext = _transform(v, plaintext)
        v + ciphertext
      end

      def open(ciphertext, associated_data = [])
        v = ciphertext.slice(0, AES::BLOCK_SIZE)
        ciphertext = ciphertext.slice(AES::BLOCK_SIZE..-1)
        plaintext = _transform(v, ciphertext)

        t = _s2v(plaintext, associated_data)
        raise IntegrityError, "ciphertext verification failure!" unless Util.ct_equal(t, v)

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

      def _s2v(plaintext, associated_data = [])
        inputs = []
        inputs.concat(Array(associated_data))
        inputs << plaintext

        cmac = CMAC.new(@key1)

        if inputs.empty?
          data = AES::ZERO_BLOCK[0, AES::BLOCK_SIZE - 1] + "\x01"
          return cmac.digest(data)
        end

        d = cmac.digest(AES::ZERO_BLOCK)

        inputs.each_with_index do |input, index|
          break if index == inputs.size - 1

          d = Util.double(d)
          block = cmac.digest(input)
          d = Util.xor(d, block)
        end

        input = inputs.last

        if input.bytesize >= AES::BLOCK_SIZE
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
