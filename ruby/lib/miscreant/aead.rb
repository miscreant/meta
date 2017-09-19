# encoding: binary
# frozen_string_literal: true

module Miscreant
  # The AEAD class provides Authenticated Encryption with Associated Data
  #
  # If you're looking for the API to encrypt something, congratulations!
  # This is the one you probably want to use. This class provides a high-level
  # interface to Miscreant's misuse-resistant encryption.
  class AEAD
    # Create a new AEAD encryptor instance.
    #
    # You will need to select an algorithm to use, passed as a string:
    #
    # * "AES-SIV" (RFC 5297): the original AES-SIV function, based on CMAC
    # * "AES-PMAC-SIV": a parallelizable AES-SIV alternative
    #
    # Choose AES-PMAC-SIV if you'd like better performance.
    # Choose AES-SIV if you'd like wider compatibility: AES-PMAC-SIV is
    # presently implemented in the Miscreant libraries.
    #
    # @param alg ["AES-SIV", "AES-PMAC-SIV"] cryptographic algorithm to use
    # @param key [String] 32-byte or 64-byte random Encoding::BINARY secret key
    def initialize(alg, key)
      Internals::Util.validate_bytestring(key, length: [32, 64])

      case alg
      when "AES-SIV", "AES-CMAC-SIV"
        mac = :CMAC
      when "AES-PMAC-SIV"
        mac = :PMAC
      else raise ArgumentError, "unsupported algorithm: #{alg.inspect}"
      end

      @siv = SIV.new(key, mac)
    end

    # Inspect this AES-SIV instance
    #
    # @return [String] description of this instance
    def inspect
      to_s
    end

    # Encrypt a message, authenticating it along with the associated data
    #
    # @param plaintext [String] an Encoding::BINARY string to encrypt
    # @param nonce [String] a unique-per-message value
    # @param ad [String] optional data to authenticate along with the message
    #
    # @return [String] encrypted ciphertext
    def seal(plaintext, nonce:, ad: "")
      raise TypeError, "expected String, got #{nonce.class}" unless nonce.is_a?(String)
      raise TypeError, "expected String, got #{ad.class}" unless ad.is_a?(String)

      @siv.seal(plaintext, [ad, nonce])
    end

    # Verify and decrypt aciphertext, authenticating it along with the associated data
    #
    # @param ciphertext [String] an Encoding::BINARY string to decrypt
    # @param nonce [String] a unique-per-message value
    # @param associated_data [String] optional data to authenticate along with the message
    #
    # @raise [Miscreant::IntegrityError] ciphertext and/or associated data are corrupt or tampered with
    # @return [String] decrypted plaintext
    def open(ciphertext, nonce:, ad: "")
      raise TypeError, "expected nonce to be String, got #{nonce.class}" unless nonce.is_a?(String)
      raise TypeError, "expected ad to be String, got #{ad.class}" unless ad.is_a?(String)

      @siv.open(ciphertext, [ad, nonce])
    end
  end
end
