# encoding: binary
# frozen_string_literal: true

module Miscreant
  module Internals
    # A 128-bit block (i.e. for AES)
    class Block # :nodoc:
      # Size of an AES block in bytes
      SIZE = 16

      # Minimal irreducible polynomial for a 128-bit block size
      R = 0x87

      attr_reader :data

      # Create a new Block, optionally from the given data
      def initialize(data = nil)
        if data
          @data = Util.validate_bytestring("block data", data, length: SIZE)
        else
          @data = "\0".b * SIZE
        end
      end

      # Inspect the contents of the block in hex
      def inspect
        "#<#{self.class} data:\"#{@data.unpack('H*').first}\">"
      end

      # Retrieve the value of the byte at the given index as an integer
      def [](n)
        raise IndexError, "n must be zero or greater (got #{n})" if n < 0
        raise IndexError, "n must be less than #{SIZE} (got #{n})" unless n < SIZE

        @data.getbyte(n)
      end

      # Set the value of the byte at the given index as an integer
      def []=(n, byte)
        @data.setbyte(n, byte)
      end

      # Reset the value of this block to all zeroes
      def clear
        SIZE.times { |n| @data[n] = 0 }
      end

      # Copy the contents of another block into this block
      def copy(other_block)
        SIZE.times { |n| @data[n] = other_block.data[n] }
      end

      # Double a value over GF(2^128):
      #
      #     a<<1 if firstbit(a)=0
      #     (a<<1) ⊕ 0¹²⁰10000111 if firstbit(a)=1
      #
      def dbl
        overflow = 0
        words = @data.unpack("N4").reverse

        words.map! do |word|
          new_word = (word << 1) & 0xFFFFFFFF
          new_word |= overflow
          overflow = (word & 0x80000000) >= 0x80000000 ? 1 : 0
          new_word
        end

        @data = words.reverse.pack("N4")
        @data[-1] = (@data[-1].ord ^ Util.ct_select(overflow, R, 0)).chr
        self
      end

      # Encrypt this block in-place, replacing its current contents with
      # their ciphertext under the given block cipher
      #
      # @param cipher [Miscreant::Internals::AES::BlockCipher] block cipher to encrypt with
      def encrypt(cipher)
        raise TypeError, "invalid cipher: #{cipher.class}" unless cipher.is_a?(AES::BlockCipher)

        # TODO: more efficient in-place encryption
        @data = cipher.encrypt(@data)
      end

      # XOR the given data into the current block in-place
      #
      # @param value [AES::Block, String] a block or String to XOR into this one
      def xor_in_place(value)
        case value
        when Block
          value = value.data
        when String
          Util.validate_bytestring("value", value, length: SIZE)
        else raise TypeError, "invalid XOR input: #{value.class}"
        end

        SIZE.times do |i|
          self[i] ^= value.getbyte(i)
        end
      end
    end
  end
end
