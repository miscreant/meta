# encoding: binary
# frozen_string_literal: true

module Miscreant
  module Internals
    module AES # :nodoc:
      # The AES-CTR unauthenticated stream cipher
      class CTR # :nodoc:
        # Create a new AES-CTR instance
        #
        # @param key [String] 16-byte or 32-byte Encoding::BINARY cryptographic key
        def initialize(key)
          Util.validate_bytestring(key, length: [16, 32])
          @cipher = OpenSSL::Cipher::AES.new(key.bytesize * 8, :CTR)
          @cipher.encrypt
          @cipher.key = key
        end

        # Inspect this AES-CTR instance
        #
        # @return [String] description of this instance
        def inspect
          to_s
        end

        # Encrypt the given message using the given counter (i.e. IV)
        #
        # @param iv [String] initial counter value as a 16-byte Encoding::BINARY string
        # @param message [String] message to be encrypted
        def encrypt(iv, message)
          Util.validate_bytestring(iv, length: Block::SIZE)
          return "".b if message.empty?

          @cipher.iv = iv
          @cipher.update(message) + @cipher.final
        end
      end
    end
  end
end
