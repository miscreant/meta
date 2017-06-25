# encoding: binary
# frozen_string_literal: true

module SIVChain
  # The Advanced Encryption Standard Block Cipher
  module AES
    # The AES-CMAC message authentication code
    class CMAC
      Exception = Class.new(StandardError)
      ZeroBlock = ("\0" * 16).b.freeze
      ConstantBlock = (("\0" * 15) + "\x87").b.freeze

      def initialize(key)
        raise TypeError, "expected String, got #{key.class}" unless key.is_a?(String)
        raise ArgumentError, "key must be Encoding::BINARY" unless key.encoding == Encoding::BINARY

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

        if message.empty? || message.length % 16 != 0
          message = _pad(message)
          final_block = @key2
        else
          final_block = @key1
        end

        last_ciphertext = ZeroBlock
        count = message.length / 16
        range = Range.new(0, count - 1)
        blocks = range.map { |i| message.slice(16 * i, 16) }
        blocks.each_with_index do |block, i|
          block = Util.xor(final_block, block) if i == range.last
          block = Util.xor(block, last_ciphertext)
          last_ciphertext = _encrypt_block(block)
        end

        last_ciphertext
      end

      private

      def _pad(message)
        padded_length = message.length + 16 - (message.length % 16)
        message += "\x80"
        message.ljust(padded_length, "\0")
      end

      def _encrypt_block(block)
        @cipher.update(block) + @cipher.final
      end

      def _generate_subkeys
        key0 = _encrypt_block(ZeroBlock)
        key1 = Util.double(key0)
        key2 = Util.double(key1)
        [key1, key2]
      end
    end
  end
end
