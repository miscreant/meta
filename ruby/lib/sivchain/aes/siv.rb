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

        @mac_key = key.slice(0, length)
        @enc_key = key.slice(length..-1)
      end

      def inspect
        to_s
      end

      def seal(plaintext, associated_data = [])
        v = _s2v(associated_data, plaintext)
        ciphertext = _transform(v, plaintext)
        v + ciphertext
      end

      def open(ciphertext, associated_data = [])
        v = ciphertext.slice(0, AES::BLOCK_SIZE)
        ciphertext = ciphertext.slice(AES::BLOCK_SIZE..-1)
        plaintext = _transform(v, ciphertext)

        t = _s2v(associated_data, plaintext)
        raise IntegrityError, "ciphertext verification failure!" unless Util.ct_equal(t, v)

        plaintext
      end

      private

      def _transform(v, data)
        return "".b if data.empty?

        cipher = OpenSSL::Cipher::AES.new(@mac_key.length * 8, :CTR)
        cipher.encrypt
        cipher.iv = Util.zero_iv_bits(v)
        cipher.key = @enc_key
        cipher.update(data) + cipher.final
      end

      # The S2V operation consists of the doubling and XORing of the outputs
      # of the pseudo-random function CMAC.
      #
      # See Section 2.4 of RFC 5297 for more information
      def _s2v(associated_data, plaintext)
        # Note: the standalone S2V returns CMAC(1) if the number of passed
        # vectors is zero, however in SIV construction this case is never
        # triggered, since we always pass plaintext as the last vector (even
        # if it's zero-length), so we omit this case.
        cmac = CMAC.new(@mac_key)
        d = cmac.digest(AES::ZERO_BLOCK)

        associated_data.each do |ad|
          d = Util.dbl(d)
          d = Util.xor(d, cmac.digest(ad))
        end

        if plaintext.bytesize >= AES::BLOCK_SIZE
          d = Util.xorend(plaintext, d)
        else
          d = Util.dbl(d)
          d = Util.xor(d, Util.pad(plaintext, AES::BLOCK_SIZE))
        end

        cmac.digest(d)
      end
    end
  end
end
