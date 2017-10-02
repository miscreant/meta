"""pmac.py: The Parallel Message Authentication Code (PMAC)"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, modes
)

from .. import (block, ct, ctz)
from ..block import Block

# Number of L blocks to precompute
# TODO: dynamically compute these as needed
PRECOMPUTED_BLOCKS = 31

class PMAC(object):
    """The Parallel Message Authentication Code"""

    def __init__(self, algorithm, backend=default_backend()):
        # NOTE: the one acceptable use of ECB mode is constructing higher-level
        # cryptographic primitives. In this case, we're using it to implement PMAC.
        self.cipher = Cipher(algorithm, modes.ECB(), backend)

        # L is defined as follows (quoted from the PMAC paper):
        #
        # Equation 1:
        #
        #     a * x =
        #         a<<1 if firstbit(a)=0
        #         (a<<1) xor (0**120)10000111 if firstbit(a)=1
        #
        # Equation 2:
        #
        #     a * x^-1 =
        #         a>>1 if lastbit(a)=0
        #         (a>>1) xor 1(0**120)1000011 if lastbit(a)=1
        #
        # Let L(0) <- L. For i in [1..PRECOMPUTED_BLOCKS], compute
        # L(i) <- L(i - 1) * x by Equation (1) using a shift and a
        # conditional xor.
        #
        # Compute L(-1) <- L * x^-1 by Equation (2), using a shift and a
        # conditional xor.
        #
        # Save the values L(-1), L(0), L(1), L(2), ..., L(PRECOMPUTED_BLOCKS)
        # in a table.
        #
        # (Alternatively, [ed: as we have done in this codebase] defer computing
        # some or  all of these L(i) values until the value is actually needed.)
        self.l = [None] * PRECOMPUTED_BLOCKS
        tmp = Block()
        tmp.encrypt(self.cipher)

        for i in range(PRECOMPUTED_BLOCKS):
            self.l[i] = tmp.clone()
            tmp.dbl()

        # lInv contains the multiplicative inverse (i.e. right shift) of the first
        # l-value, computed as described above, and is XORed into the tag in the
        # event the message length is a multiple of the block size
        self.l_inv = self.l[0].clone()
        last_bit = self.l_inv.data[block.SIZE - 1] & 1

        for i in reversed(range(1, block.SIZE)):
            carry = ct.select(self.l_inv.data[i - 1] & 1, 0x80, 0)
            self.l_inv.data[i] = (self.l_inv.data[i] >> 1) | carry

        self.l_inv.data[0] >>= 1
        self.l_inv.data[0] ^= ct.select(last_bit, 0x80, 0)
        self.l_inv.data[block.SIZE - 1] ^= ct.select(last_bit, block.R >> 1, 0)

        # digest contains the PMAC tag-in-progress
        self.digest = Block()

        # offset is a block specific tweak to the input message
        self.offset = Block()

        # buffer contains a part of the input message, processed a block-at-a-time
        self.buffer = Block()

        # position marks the end of plaintext in the buffer
        self.position = 0

        # counter is the number of blocks we have MAC'd so far
        self.counter = 0

        # finished is set true when we are done processing a message, and forbids
        # any subsequent writes until we reset the internal state
        self.finished = False

    def reset(self):
        """Clears the digest state, starting a new digest"""
        self.digest.clear()
        self.offset.clear()
        self.buffer.clear()
        self.position = 0
        self.counter = 0
        self.finished = False

    def update(self, message):
        """Update the PMAC internal state with the given message"""
        if self.finished:
            raise RuntimeError("pmac: already finished")

        msg_pos = 0
        msg_len = len(message)
        remaining = block.SIZE - self.position

        if msg_len > remaining:
            self.buffer.data[self.position:] = message[:remaining]
            msg_pos += remaining
            msg_len -= remaining
            self.__process_buffer()

        while msg_len > block.SIZE:
            self.buffer.data[:] = message[msg_pos:msg_pos+block.SIZE]
            msg_pos += block.SIZE
            msg_len -= block.SIZE
            self.__process_buffer()

        if msg_len > 0:
            self.buffer.data[self.position:self.position+msg_len] = message[msg_pos:]
            self.position += msg_len

        return len(message)

    def finalize(self):
        """Return the computed PMAC tag for the data we've hashed so far"""
        if self.finished:
            raise RuntimeError("pmac: already finished")

        if self.position == block.SIZE:
            self.digest.xor_in_place(self.buffer)
            self.digest.xor_in_place(self.l_inv)
        else:
            for i in range(self.position):
                self.digest.data[i] ^= self.buffer.data[i]
            self.digest.data[self.position] ^= 0x80

        self.digest.encrypt(self.cipher)
        self.finished = True

        return bytes(self.digest.data)

    def __process_buffer(self):
        self.offset.xor_in_place(self.l[ctz.trailing_zeroes(self.counter + 1)])
        self.buffer.xor_in_place(self.offset)
        self.counter += 1

        self.buffer.encrypt(self.cipher)
        self.digest.xor_in_place(self.buffer)
        self.position = 0
