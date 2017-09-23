# encoding: binary
# frozen_string_literal: true

require "openssl"
require "securerandom"

require "miscreant/version"
require "miscreant/aead"
require "miscreant/aes/siv"
require "miscreant/internals"

# Miscreant: A misuse-resistant symmetric encryption library
module Miscreant
  # Parent of all cryptography-related errors
  CryptoError = Class.new(StandardError)

  # Ciphertext failed to verify as authentic
  IntegrityError = Class.new(CryptoError)

  # Hide internals from the outside world
  private_constant :Internals
end
