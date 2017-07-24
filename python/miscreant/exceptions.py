"""exceptions.py: Custom exceptions used by Miscreant"""


class CryptoError(Exception):
    """Parent of all cryptography-related errors"""


class IntegrityError(CryptoError):
    """Ciphertext failed to verify as authentic"""
