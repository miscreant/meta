"""siv.py: The AES-SIV misuse resistant authenticated encryption cipher"""

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import (
    cmac, constant_time
)
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from .. import (block, exceptions)
from ..block import Block

class SIV(object):
    """The AES-SIV misuse resistant authenticated encryption cipher"""

    @staticmethod
    def generate_key(size=32):
        """Generate a new random AES-SIV key of the given size"""
        if size != 32 and size != 64:
            raise ValueError("key size must be 32 or 64 bytes")

        return os.urandom(size)

    def __init__(self, key, mac=cmac.CMAC):
        """Create a new SIV object"""
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")

        if len(key) != 32 and len(key) != 64:
            raise ValueError("key size must be 32 or 64 bytes")

        length = len(key) >> 1
        self.mac_key = key[0:length]
        self.enc_key = key[length:]
        self.mac_alg = mac

    def seal(self, plaintext, associated_data=None):
        """Encrypt a message using AES-SIV, authenticating and the associated data"""
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        if associated_data is None:
            associated_data = []

        v = self.__s2v(associated_data, plaintext)
        ciphertext = self.__transform(v, plaintext)
        return v + ciphertext

    def open(self, ciphertext, associated_data=None):
        """Verify and decrypt an AES-SIV ciphertext, authenticating and the associated data"""
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")

        if associated_data is None:
            associated_data = []

        v = ciphertext[0:block.SIZE]
        ciphertext = ciphertext[block.SIZE:]
        plaintext = self.__transform(v, ciphertext)

        t = self.__s2v(associated_data, plaintext)
        if not constant_time.bytes_eq(t, v):
            raise exceptions.IntegrityError("ciphertext verification failure!")

        return plaintext

    def __transform(self, v, message):
        """Performs raw unauthenticted encryption or decryption of the message"""
        if not message:
            return b""

        # "We zero-out the top bit in each of the last two 32-bit words
        # of the IV before assigning it to Ctr"
        # -- http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
        iv = bytearray(v)
        iv[8] = iv[8] & 0x7f
        iv[12] = iv[12] & 0x7f

        encryptor = Cipher(
            algorithms.AES(self.enc_key),
            modes.CTR(bytes(iv)),
            backend=default_backend()
        ).encryptor()

        return encryptor.update(message) + encryptor.finalize()

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
        d = Block()
        d.xor_in_place(self.__mac(d.data))

        for ad in associated_data:
            if not isinstance(ad, bytes):
                raise TypeError("associated data must be bytes")

            d.dbl()
            d.xor_in_place(self.__mac(ad))

        if len(plaintext) >= block.SIZE:
            mac = self.mac_alg(algorithms.AES(self.mac_key), backend=default_backend())
            difference = len(plaintext) - block.SIZE
            mac.update(plaintext[:difference])
            d.xor_in_place(plaintext[difference:])
            mac.update(bytes(d.data))
            return mac.finalize()

        d.dbl()
        pt_length = len(plaintext)
        pt_bytearray = bytearray(plaintext)
        for i in range(pt_length):
            d.data[i] ^= pt_bytearray[i]
        d.data[pt_length] ^= 0x80
        return self.__mac(d.data)

    def __mac(self, message):
        mac = self.mac_alg(algorithms.AES(self.mac_key), backend=default_backend())
        mac.update(bytes(message))
        return mac.finalize()
