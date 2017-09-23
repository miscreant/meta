# encoding: binary
# frozen_string_literal: true

module Miscreant
  # The Advanced Encryption Standard
  module AES
    # The Parallel Message Authentication Code
    class PMAC
      # Number of L blocks to precompute (i.e. µ in the PMAC paper)
      # TODO: dynamically compute these as needed
      PRECOMPUTED_BLOCKS = 31

      # Create a new PMAC instance
      #
      # @param key [String] 16-byte or 32-byte Encoding::BINARY cryptographic key
      def initialize(key)
        @cipher = Internals::AES::BlockCipher.new(key)

        # L is defined as follows (quoted from the PMAC paper):
        #
        # Equation 1:
        #
        #     a · x =
        #         a<<1 if firstbit(a)=0
        #         (a<<1) ⊕ 0¹²⁰10000111 if firstbit(a)=1
        #
        # Equation 2:
        #
        #     a · x⁻¹ =
        #         a>>1 if lastbit(a)=0
        #         (a>>1) ⊕ 10¹²⁰1000011 if lastbit(a)=1
        #
        # Let L(0) ← L. For i ∈ [1..µ], compute L(i) ← L(i − 1) · x by
        # Equation (1) using a shift and a conditional xor.
        #
        # Compute L(−1) ← L · x⁻¹ by Equation (2), using a shift and a
        # conditional xor.
        #
        # Save the values L(−1), L(0), L(1), L(2), ..., L(µ) in a table.
        # (Alternatively, [ed: as we have done in this codebase] defer computing
        # some or  all of these L(i) values until the value is actually needed.)
        @l = []
        tmp = Internals::Block.new
        tmp.encrypt(@cipher)

        PRECOMPUTED_BLOCKS.times.each do
          block = Internals::Block.new(tmp.data.dup)
          block.data.freeze
          block.freeze

          @l << block
          tmp.dbl
        end

        @l.freeze

        # Compute L(−1) ← L · x⁻¹:
        #
        #     a>>1 if lastbit(a)=0
        #     (a>>1) ⊕ 10¹²⁰1000011 if lastbit(a)=1
        #
        @l_inv = Internals::Block.new(@l[0].data.dup)
        last_bit = @l_inv[Internals::Block::SIZE - 1] & 0x01

        (Internals::Block::SIZE - 1).downto(1) do |i|
          carry = Internals::Util.ct_select(@l_inv[i - 1] & 1, 0x80, 0)
          @l_inv[i] = (@l_inv[i] >> 1) | carry
        end

        @l_inv[0] >>= 1
        @l_inv[0] ^= Internals::Util.ct_select(last_bit, 0x80, 0)
        @l_inv[Internals::Block::SIZE - 1] ^= Internals::Util.ct_select(last_bit, Internals::Block::R >> 1, 0)
        @l_inv.freeze
        @l_inv.data.freeze
      end

      # Inspect this PMAC instance
      #
      # @return [String] description of this instance
      def inspect
        to_s
      end

      # Compute the PMAC of the given input message in a single shot,
      # outputting the MAC tag.
      #
      # Unlike other PMAC implementations, this one does not support
      # incremental processing/IUF operation. (Though that would enable
      # slightly more efficient decryption for AES-SIV)
      #
      # @param message [String] an Encoding::BINARY string to authenticate
      #
      # @return [String] PMAC tag
      def digest(message)
        Internals::Util.validate_bytestring("message", message)

        offset = Internals::Block.new
        tmp = Internals::Block.new
        tag = Internals::Block.new
        ctr = 0
        remaining = message.bytesize

        while remaining > Internals::Block::SIZE
          offset.xor_in_place(@l.fetch(Internals::Util.ctz(ctr + 1)))

          tmp.copy(offset)
          tmp.xor_in_place(message[ctr * Internals::Block::SIZE, Internals::Block::SIZE])
          tmp.encrypt(@cipher)
          tag.xor_in_place(tmp)

          ctr += 1
          remaining -= Internals::Block::SIZE
        end

        if remaining == Internals::Block::SIZE
          tag.xor_in_place(message[(ctr * Internals::Block::SIZE)..-1])
          tag.xor_in_place(@l_inv)
        else
          remaining.times { |i| tag[i] ^= message.getbyte((ctr * Internals::Block::SIZE) + i) }
          tag[remaining] ^= 0x80
        end

        tag.encrypt(@cipher)
        tag.data
      end
    end
  end
end
