# encoding: binary
# frozen_string_literal: true

module Miscreant
  module Internals
    module MAC # :nodoc:
      # The AES-CMAC message authentication code
      class CMAC # :nodoc:
        # Create a new AES-CMAC instance
        #
        # @param key [String] 16-byte or 32-byte Encoding::BINARY cryptographic key
        def initialize(key)
          @cipher = AES::BlockCipher.new(key)

          @subkey1 = Block.new
          @subkey1.encrypt(@cipher)
          @subkey1.dbl

          @subkey2 = @subkey1.dup
          @subkey2.dbl
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
          Util.validate_bytestring("message", message)

          if message.empty? || message.length % Block::SIZE != 0
            message = Util.pad(message, Block::SIZE)
            subkey = @subkey2
          else
            subkey = @subkey1
          end

          count = message.length / Block::SIZE
          digest = Block.new

          count.times do |i|
            digest.xor_in_place(message[Block::SIZE * i, Block::SIZE])
            digest.xor_in_place(subkey) if i == count - 1
            digest.encrypt(@cipher)
          end

          digest.data
        end
      end
    end
  end
end
