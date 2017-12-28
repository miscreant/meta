# encoding: binary
# frozen_string_literal: true

require "miscreant/version"

require "openssl"
require "securerandom"

require "miscreant/aead"
require "miscreant/aes/cmac"
require "miscreant/aes/pmac"
require "miscreant/aes/siv"
require "miscreant/internals"
require "miscreant/stream"

# Miscreant: A misuse-resistant symmetric encryption library
module Miscreant
  # Parent of all cryptography-related errors
  CryptoError = Class.new(StandardError)

  # Ciphertext failed to verify as authentic
  IntegrityError = Class.new(CryptoError)

  # Integer value overflowed
  OverflowError = Class.new(StandardError)

  # Hide internals from the outside world
  private_constant :Internals
end
