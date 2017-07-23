# encoding: binary
# frozen_string_literal: true

module SIVChain
  module AES
    # The AES-CMAC message authentication code
    class CMAC
      # Create a new AES-CMAC instance
      #
      # @param key [String] 16-byte or 32-byte Encoding::BINARY cryptographic key
      #
      # @return [SIVChain::AES::CMAC] new AES-CMAC instance
      def initialize(key)
        raise TypeError, "expected String, got #{key.class}" unless key.is_a?(String)
        raise ArgumentError, "key must be Encoding::BINARY" unless key.encoding == Encoding::BINARY
        raise ArgumentError, "key must be 32 or 64 bytes" unless [16, 32].include?(key.length)

        # The only valid use of ECB mode: constructing higher-level cryptographic primitives
        @cipher = OpenSSL::Cipher.new("AES-#{key.length * 8}-ECB")
        @cipher.encrypt
        @cipher.padding = 0
        @cipher.key = key
        @key1, @key2 = _generate_subkeys
      end

      # Inspect this AES-CMAC instance
      #
      # @return [String] description of this instance
      def inspect
        to_s
      end

      # Compute the AES-CMAC of the given input message in a single shot,
      # outputting the MAC tag.
      #
      # Unlike other AES-CMAC implementations, this one does not support
      # incremental processing/IUF operation. (Though that would enable
      # slightly more efficient decryption for AES-SIV)
      #
      # @param message [String] an Encoding::BINARY string to authenticate
      #
      # @return [String] CMAC tag
      def digest(message)
        raise TypeError, "expected String, got #{message.class}" unless message.is_a?(String)
        raise ArgumentError, "message must be Encoding::BINARY" unless message.encoding == Encoding::BINARY

        if message.empty? || message.length % AES::BLOCK_SIZE != 0
          message = Util.pad(message, AES::BLOCK_SIZE)
          final_block = @key2
        else
          final_block = @key1
        end

        count = message.length / AES::BLOCK_SIZE
        result = AES::ZERO_BLOCK

        count.times do |i|
          block = message.slice(AES::BLOCK_SIZE * i, AES::BLOCK_SIZE)
          block = Util.xor(final_block, block) if i == count - 1
          block = Util.xor(block, result)
          result = @cipher.update(block) + @cipher.final
        end

        result
      end

      private

      def _generate_subkeys
        key0 = @cipher.update(AES::ZERO_BLOCK) + @cipher.final
        key1 = Util.dbl(key0)
        key2 = Util.dbl(key1)
        [key1, key2]
      end
    end
  end
end
