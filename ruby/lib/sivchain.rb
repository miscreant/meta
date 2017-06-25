# frozen_string_literal: true

require "openssl"

require "sivchain/version"

require "sivchain/aes"
require "sivchain/aes/siv"
require "sivchain/aes/cmac"
require "sivchain/util"

# Advanced symmetric encryption using the AES-SIV (RFC 5297) and CHAIN constructions
module SIVChain
  # Parent of all cryptography-related errors
  CryptoError = Class.new(StandardError)

  # Ciphertext failed to verify as authentic
  IntegrityError = Class.new(CryptoError)
end
