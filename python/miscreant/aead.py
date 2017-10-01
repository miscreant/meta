"""aead.py: Authenticated Encryption with Associated Data"""

import os

from cryptography.hazmat.primitives.cmac import CMAC

from .aes.siv import SIV
from .mac.pmac import PMAC

class AEAD(object):
    """The AEAD class provides Authenticated Encryption with Associated Data

    If you're looking for the API to encrypt something, congratulations!
    This is the one you probably want to use. This class provides a high-level
    interface to Miscreant's misuse-resistant encryption.
    """

    @staticmethod
    def generate_key(size=32):
        """Generate a new random AES-SIV key of the given size"""
        return SIV.generate_key(size)

    @staticmethod
    def generate_nonce(size=16):
        """Generate a random "nonce" (i.e. number used once) value"""
        return os.urandom(size)

    def __init__(self, alg, key):
        """Create a new AEAD encryptor instance. You will need to select an
        algorithm to use, passed as a string:

        * "AES-SIV" (RFC 5297): the original AES-SIV function, based on CMAC
        * "AES-PMAC-SIV": a parallelizable AES-SIV alternative

        Choose AES-PMAC-SIV if you'd like better performance for large messages.

        Choose AES-SIV if you'd like wider compatibility: AES-PMAC-SIV is
        presently implemented in the Miscreant libraries, whereas AES-SIV
        libraries are available for many languages outside the ones provided
        by the Miscreant ecosystem.
        """
        if alg == "AES-SIV" or alg == "AES-CMAC-SIV":
            mac = CMAC
        elif alg == "AES-PMAC-SIV":
            mac = PMAC
        else:
            raise ValueError("unsupported algorithm: " + repr(alg))

        self.siv = SIV(key, mac)

    def seal(self, plaintext, nonce=None, associated_data=b""):
        """Encrypt a message, authenticating it along with the associated data"""

        if not isinstance(nonce, bytes):
            raise TypeError("nonce must be bytes")

        if not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be bytes")

        return self.siv.seal(plaintext, [associated_data, nonce])

    def open(self, ciphertext, nonce=None, associated_data=b""):
        """Verify and decrypt a ciphertext, authenticating it along with the associated data"""

        if not isinstance(nonce, bytes):
            raise TypeError("nonce must be bytes")

        if not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be bytes")

        return self.siv.open(ciphertext, [associated_data, nonce])
