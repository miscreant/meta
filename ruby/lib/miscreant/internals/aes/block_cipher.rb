# encoding: binary
# frozen_string_literal: true

module Miscreant
  module Internals
    module AES # :nodoc:
      # The AES cipher in a raw block mode (a.k.a. ECB mode)
      #
      # NOTE: The only valid use of ECB mode is constructing higher-level
      # cryptographic primitives. This library uses this class to implement
      # the CMAC and PMAC message authentication codes.
      class BlockCipher # :nodoc:
        # Create a new block cipher instance
        #
        # @param key [String] a random 16-byte or 32-byte Encoding::BINARY encryption key
        #
        # @raise [TypeError] the key was not a String
        # @raise [ArgumentError] the key was the wrong length or encoding
        def initialize(key)
          Util.validate_bytestring(key, length: [16, 32])

          @cipher = OpenSSL::Cipher.new("AES-#{key.length * 8}-ECB")
          @cipher.encrypt
          @cipher.padding = 0
          @cipher.key = key
        end

        # Inspect this AES block cipher instance
        #
        # @return [String] description of this instance
        def inspect
          to_s
        end

        # Encrypt the given AES block-sized message
        #
        # @param message [String] a 16-byte Encoding::BINARY message to encrypt
        #
        # @raise [TypeError] the message was not a String
        # @raise [ArgumentError] the message was the wrong length
        def encrypt(message)
          Util.validate_bytestring(message, length: Block::SIZE)
          @cipher.update(message) + @cipher.final
        end
      end
    end
  end
end
