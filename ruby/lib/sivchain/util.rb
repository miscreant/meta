# encoding: binary
# frozen_string_literal: true

module SIVChain
  # Utility functions
  module Util
    DOUBLE_CONSTANT = (("\x0" * 15) + "\x87").freeze

    module_function

    # Perform a doubling operation as described in the CMAC and SIV papers
    def double(value)
      overflow = 0
      words = value.unpack("N4").reverse
      words = words.map do |word|
        new_word = (word << 1) & 0xFFFFFFFF
        new_word |= overflow
        overflow = (word & 0x80000000) >= 0x80000000 ? 1 : 0
        new_word
      end
      result = words.reverse.pack("N4")

      # TODO: not constant time!
      return result if value[0].ord < 0x80
      xor(result, DOUBLE_CONSTANT)
    end

    # Perform an xor on arbitrary bytestrings
    def xor(a, b)
      length = [a.length, b.length].min
      output = "\0" * length
      length.times do |i|
        output[i] = (a[i].ord ^ b[i].ord).chr
      end
      output
    end

    # Perform a constant time-ish comparison of two bytestrings
    def ct_equal(a, b)
      return false unless a.bytesize == b.bytesize

      l = a.unpack("C*")
      r = 0
      i = -1

      b.each_byte { |v| r |= v ^ l[i += 1] }

      r.zero?
    end
  end
end
