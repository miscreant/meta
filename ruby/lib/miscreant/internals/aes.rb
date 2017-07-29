# encoding: binary
# frozen_string_literal: true

module Miscreant
  module Internals
    # The Advanced Encryption Standard Block Cipher
    module AES # :nodoc:
      # Size of an AES block (i.e. input/output from the AES function)
      BLOCK_SIZE = 16

      # A bytestring of all zeroes, the same length as an AES block
      ZERO_BLOCK = ("\0" * BLOCK_SIZE).freeze
    end
  end
end
