# encoding: binary
# frozen_string_literal: true

module Miscreant
  # The STREAM online authenticated encryption construction.
  # See <https://eprint.iacr.org/2015/189.pdf> for definition.
  #
  # Miscreant's implementation of STREAM uses an 8-byte (64-bit) nonce
  # prefix along with a 32-bit counter and 1-byte "last block" flag
  module STREAM
    # Size of a nonce required by STREAM in bytes
    NONCE_SIZE = 8

    # Byte flag indicating this is the last block in the STREAM (otherwise 0)
    LAST_BLOCK_FLAG = 1

    # Maximum value of the STREAM counter
    COUNTER_MAX = 2**32

    # Raised if we attempt to continue an already-finished STREAM
    FinishedError = Class.new(StandardError)

    # A STREAM encryptor
    #
    # This corresponds to the ℰ stream encryptor object as defined in the paper
    # Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance
    class Encryptor
      # Create a new STREAM encryptor.
      #
      # @param alg ["AES-SIV", "AES-PMAC-SIV"] cryptographic algorithm to use
      # @param key [String] 32-byte or 64-byte random Encoding::BINARY secret key
      # @param nonce [String] 8-byte nonce
      #
      # @raise [TypeError] nonce is not a String
      # @raise [ArgumentError] nonce is wrong length or not Encoding::BINARY
      def initialize(alg, key, nonce)
        @aead = AEAD.new(alg, key)
        @nonce_encoder = NonceEncoder.new(nonce)
      end

      # Encrypt the next message in the stream
      #
      # @param plaintext [String] plaintext message to encrypt
      # @param ad [String] (optional) associated data to authenticate
      # @param last_block [true, false] is this the last block in the STREAM?
      #
      # @return [String] ciphertext message
      def seal(plaintext, ad: "", last_block: false)
        @aead.seal(plaintext, nonce: @nonce_encoder.next(last_block), ad: ad)
      end

      # Inspect this STREAM encryptor instance
      #
      # @return [String] description of this instance
      def inspect
        to_s
      end
    end

    # A STREAM decryptor
    #
    # This corresponds to the 𝒟 stream decryptor object as defined in the paper
    # Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance
    class Decryptor
      # Create a new STREAM decryptor.
      #
      # @param alg ["AES-SIV", "AES-PMAC-SIV"] cryptographic algorithm to use
      # @param key [String] 32-byte or 64-byte random Encoding::BINARY secret key
      # @param nonce [String] 8-byte nonce
      #
      # @raise [TypeError] nonce is not a String
      # @raise [ArgumentError] nonce is wrong length or not Encoding::BINARY
      def initialize(alg, key, nonce)
        @aead = AEAD.new(alg, key)
        @nonce_encoder = NonceEncoder.new(nonce)
      end

      # Decrypt the next message in the stream
      #
      # @param ciphertext [String] cipher message to encrypt
      # @param ad [String] (optional) associated data to authenticate
      # @param last_block [true, false] is this the last block in the STREAM?
      #
      # @raise [Miscreant::IntegrityError] ciphertext and/or associated data are corrupt or tampered with
      # @return [String] plaintext message
      def open(ciphertext, ad: "", last_block: false)
        @aead.open(ciphertext, nonce: @nonce_encoder.next(last_block), ad: ad)
      end

      # Inspect this STREAM encryptor instance
      #
      # @return [String] description of this instance
      def inspect
        to_s
      end
    end

    # Computes STREAM nonces based on the current position in the STREAM.
    class NonceEncoder
      # Create a new nonce encoder with the given prefix
      #
      # @param [nonce_prefix] 64-bit string used as the STREAM nonce prefix
      #
      # @raise [TypeError] nonce prefix is not a String
      # @raise [ArgumentError] nonce prefix is wrong length or not Encoding::BINARY
      def initialize(nonce_prefix)
        Internals::Util.validate_bytestring("nonce", nonce_prefix, length: NONCE_SIZE)
        @nonce_prefix = nonce_prefix
        @counter = 0
        @finished = false
      end

      # Obtain the next nonce in the stream
      #
      # @param last_block [true, false] is this the last block?
      #
      # @return [String] encoded STREAM nonce
      def next(last_block)
        raise FinishedError, "STREAM is already finished" if @finished
        @finished = last_block

        encoded_nonce = [@nonce_prefix, @counter, last_block ? LAST_BLOCK_FLAG : 0].pack("a8NC")
        @counter += 1
        raise OverflowError, "STREAM counter overflowed" if @counter >= 2**64

        encoded_nonce
      end
    end

    private_constant :NonceEncoder
  end
end
