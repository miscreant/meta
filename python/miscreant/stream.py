"""
The STREAM online authenticated encryption construction.
See <https://eprint.iacr.org/2015/189.pdf> for definition.
"""

from struct import pack
from . import exceptions
from .aead import AEAD

# Size of a nonce required by STREAM in bytes
NONCE_SIZE = 8

# Byte flag indicating this is the last block in the STREAM (otherwise 0)
LAST_BLOCK_FLAG = 1

# Maximum value of the STREAM counter
COUNTER_MAX = 2**32

class Encryptor(object):
    """"STREAM encryptor"""

    def __init__(self, alg, key, nonce):
        """Create a new STREAM encryptor"""
        self.aead = AEAD(alg, key)
        self.nonce_encoder = NonceEncoder(nonce)

    def seal(self, plaintext, associated_data=b"", last_block=False):
        """Encrypt the next message in the stream"""
        return self.aead.seal(
            plaintext,
            nonce=self.nonce_encoder.next(last_block),
            associated_data=associated_data
        )


class Decryptor(object):
    """STREAM decryptor"""

    def __init__(self, alg, key, nonce):
        """Create a new STREAM decryptor"""
        self.aead = AEAD(alg, key)
        self.nonce_encoder = NonceEncoder(nonce)

    def open(self, ciphertext, associated_data=b"", last_block=False):
        """Decrypt the next message in the stream"""
        return self.aead.open(
            ciphertext,
            nonce=self.nonce_encoder.next(last_block),
            associated_data=associated_data
        )

class NonceEncoder(object):
    """Computes STREAM nonces based on the current position in the STREAM"""

    def __init__(self, nonce_prefix):
        """Create a new NonceEncoder"""
        if not isinstance(nonce_prefix, bytes):
            raise TypeError("nonce must be bytes")

        if len(nonce_prefix) != NONCE_SIZE:
            raise ValueError("nonce must be 8-bytes")

        self.nonce_prefix = nonce_prefix
        self.counter = 0
        self.finished = False

    def next(self, last_block):
        """Obtain the next nonce in the stream"""
        if self.finished:
            raise exceptions.FinishedError("STREAM is already finished")

        self.finished = last_block

        if last_block:
            flag = LAST_BLOCK_FLAG
        else:
            flag = 0

        encoded_nonce = pack(b"!8sIB", self.nonce_prefix, self.counter, flag)
        self.counter += 1

        if self.counter >= COUNTER_MAX:
            raise exceptions.OverflowError("STREAM counter overflow")

        return encoded_nonce
