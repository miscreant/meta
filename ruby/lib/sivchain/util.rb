# encoding: binary
# frozen_string_literal: true

module SIVChain
  # Utility functions
  module Util
    module_function

    # Perform a constant time(-ish) branch operation
    def select(subject, result_if_one, result_if_zero)
      (~(subject - 1) & result_if_one) | ((subject - 1) & result_if_zero)
    end

    # Perform a doubling operation as described in the CMAC and SIV papers
    def dbl(value)
      overflow = 0
      words = value.unpack("N4").reverse

      words.map! do |word|
        new_word = (word << 1) & 0xFFFFFFFF
        new_word |= overflow
        overflow = (word & 0x80000000) >= 0x80000000 ? 1 : 0
        new_word
      end

      result = words.reverse.pack("N4")
      result[-1] = (result[-1].ord ^ select(overflow, 0x87, 0)).chr
      result
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

    # XOR the second value into the end of the first
    def xorend(a, b)
      difference = a.length - b.length

      left  = a.slice(0, difference)
      right = a.slice(difference..-1)

      left + xor(right, b)
    end

    # Pad a value up to the given length
    def pad(value, length)
      difference = length - value.length - 1
      value + "\x80" << ("\0" * difference)
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
