"""exceptions.py: Custom exceptions used by Miscreant"""


class CryptoError(Exception):
    """Parent of all cryptography-related errors"""


class IntegrityError(CryptoError):
    """Ciphertext failed to verify as authentic"""


class OverflowError(Exception):
    """Integer value overflowed"""


class FinishedError(Exception):
    """STREAM is already finished"""
