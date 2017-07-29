# frozen_string_literal: true

require "openssl"
require "securerandom"

require "miscreant/version"
require "miscreant/internals"

# Misuse-resistant symmetric encryption using the AES-SIV (RFC 5297) and CHAIN constructions
module Miscreant
  # Parent of all cryptography-related errors
  CryptoError = Class.new(StandardError)

  # Ciphertext failed to verify as authentic
  IntegrityError = Class.new(CryptoError)
end
