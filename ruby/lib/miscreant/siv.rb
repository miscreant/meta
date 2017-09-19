# encoding: binary
# frozen_string_literal: true

module Miscreant
  # The SIV misuse resistant authenticated encryption mode
  class SIV
    # Generate a new random AES-SIV key of the given size
    #
    # @param size [Integer] size of key in bytes (32 or 64)
    #
    # @return [String] newly generated AES-SIV key
    def self.generate_key(size = 32)
      raise ArgumentError, "key size must be 32 or 64 bytes" unless [32, 64].include?(size)
      SecureRandom.random_bytes(size)
    end

    # Create a new AES-SIV instance
    #
    # @param key [String] 32-byte or 64-byte Encoding::BINARY cryptographic key
    # @param mac [:CMAC, :PMAC] (optional) MAC function to use (default CMAC)
    def initialize(key, mac_class = :CMAC)
      Internals::Util.validate_bytestring(key, length: [32, 64])
      length = key.length / 2

      @mac = Internals::MAC.const_get(mac_class).new(key[0, length])
      @ctr = Internals::AES::CTR.new(key[length..-1])
    end

    # Inspect this AES-SIV instance
    #
    # @return [String] description of this instance
    def inspect
      to_s
    end

    # Encrypt a message using AES-SIV, authenticating it along with the associated data
    #
    # @param plaintext [String] an Encoding::BINARY string to encrypt
    # @param associated_data [Array<String>] optional array of message headers to authenticate
    #
    # @return [String] encrypted ciphertext
    def seal(plaintext, associated_data = [])
      raise TypeError, "expected String, got #{plaintext.class}" unless plaintext.is_a?(String)
      v = _s2v(associated_data, plaintext)
      ciphertext = @ctr.encrypt(_zero_iv_bits(v), plaintext)
      v + ciphertext
    end

    # Verify and decrypt an AES-SIV ciphertext, authenticating it along with the associated data
    #
    # @param ciphertext [String] an Encoding::BINARY string to decrypt
    # @param associated_data [Array<String>] optional array of message headers to authenticate
    #
    # @raise [Miscreant::IntegrityError] ciphertext and/or associated data are corrupt or tampered with
    # @return [String] decrypted plaintext
    def open(ciphertext, associated_data = [])
      raise TypeError, "expected String, got #{ciphertext.class}" unless ciphertext.is_a?(String)
      v = ciphertext[0, Internals::Block::SIZE]
      plaintext = @ctr.encrypt(_zero_iv_bits(v), ciphertext[Internals::Block::SIZE..-1])
      t = _s2v(associated_data, plaintext)
      raise IntegrityError, "ciphertext verification failure!" unless Internals::Util.ct_equal(t, v)

      plaintext
    end

    private

    # The S2V operation consists of the doubling and XORing of the outputs
    # of the pseudo-random function CMAC.
    #
    # See Section 2.4 of RFC 5297 for more information
    def _s2v(associated_data, plaintext)
      # Note: the standalone S2V returns CMAC(1) if the number of passed
      # vectors is zero, however in SIV construction this case is never
      # triggered, since we always pass plaintext as the last vector (even
      # if it's zero-length), so we omit this case.
      d = Internals::Block.new
      d.xor_in_place(@mac.digest(d.data))

      associated_data.each do |ad|
        d.dbl
        d.xor_in_place(@mac.digest(ad))
      end

      if plaintext.bytesize >= Internals::Block::SIZE
        # TODO: implement this more efficiently by adding IUF support to CMAC
        difference = plaintext.length - Internals::Block::SIZE
        beginning = plaintext[0, difference]
        d.xor_in_place(plaintext[difference..-1])
        msg = beginning + d.data
      else
        d.dbl
        d.xor_in_place(Internals::Util.pad(plaintext, Internals::Block::SIZE))
        msg = d.data
      end

      @mac.digest(msg)
    end

    # "We zero-out the top bit in each of the last two 32-bit words
    # of the IV before assigning it to Ctr"
    # -- http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
    def _zero_iv_bits(iv)
      iv = iv.dup
      iv.setbyte(8, iv.getbyte(8) & 0x7f)
      iv.setbyte(12, iv.getbyte(12) & 0x7f)
      iv
    end
  end
end
