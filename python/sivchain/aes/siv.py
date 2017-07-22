"""siv.py: The AES-SIV misuse resistant authenticated encryption cipher"""

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import (
    cmac, constant_time
)
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from .. import (util, exceptions)

#: Size of an AES block (i.e. input/output from the AES function)
AES_BLOCK_SIZE = 16

#: A bytestring of all zeroes, the same length as an AES block
AES_ZERO_BLOCK = b"\0" * AES_BLOCK_SIZE

class SIV(object):
    """The AES-SIV misuse resistant authenticated encryption cipher"""

    @staticmethod
    def generate_key(size = 32):
        """Generate a new random AES-SIV key of the given size"""
        if size != 32 and size != 64:
            raise ValueError("key size must be 32 or 64 bytes")

        return os.urandom(size)

    def __init__(self, key):
        """Create a new SIV object"""
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")

        if len(key) != 32 and len(key) != 64:
            raise ValueError("key size must be 32 or 64 bytes")

        length = len(key) >> 1
        self.mac_key = key[0:length]
        self.enc_key = key[length:]

    def seal(self, plaintext, associated_data = []):
        """Encrypt a message using AES-SIV, authenticating it along with the associated data"""
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        v = self.__s2v(associated_data, plaintext)
        ciphertext = self.__transform(v, plaintext)
        return v + ciphertext

    def open(self, ciphertext, associated_data = []):
        """Verify and decrypt an AES-SIV ciphertext, authenticating it along with the associated data"""
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")

        v = ciphertext[0:AES_BLOCK_SIZE]
        ciphertext = ciphertext[AES_BLOCK_SIZE:]
        plaintext = self.__transform(v, ciphertext)

        t = self.__s2v(associated_data, plaintext)
        if not constant_time.bytes_eq(t, v):
            raise exceptions.IntegrityError("ciphertext verification failure!")

        return plaintext

    def __transform(self, v, data):
        """Performs raw unauthenticted encryption or decryption of the message"""
        if not data:
            return b""

        encryptor = Cipher(
            algorithms.AES(self.enc_key),
            modes.CTR(util.zero_iv_bits(v)),
            backend=default_backend()
        ).encryptor()

        return encryptor.update(data) + encryptor.finalize()

    def __s2v(self, associated_data, plaintext):
        """
        The S2V operation consists of the doubling and XORing of the outputs
        of the pseudo-random function CMAC.

        See Section 2.4 of RFC 5297 for more information
        """

        # Note: the standalone S2V returns CMAC(1) if the number of passed
        # vectors is zero, however in SIV construction this case is never
        # triggered, since we always pass plaintext as the last vector (even
        # if it's zero-length), so we omit this case.
        d = self.__mac(AES_ZERO_BLOCK)

        for ad in associated_data:
            if not isinstance(ad, bytes):
                raise TypeError("associated data must be bytes")

            d = util.dbl(d)
            d = util.xor(d, self.__mac(ad))

        if len(plaintext) >= AES_BLOCK_SIZE:
            d = util.xorend(plaintext, d)
        else:
            d = util.dbl(d)
            d = util.xor(d, util.pad(plaintext, AES_BLOCK_SIZE))

        return self.__mac(d)

    def __mac(self, input):
        mac = cmac.CMAC(algorithms.AES(self.mac_key), backend=default_backend())
        mac.update(input)
        return mac.finalize()

