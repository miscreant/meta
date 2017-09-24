#!/usr/bin/env python

"""
test_util
----------

Tests for the `miscreant.block` module.
"""

import unittest

from miscreant.block import Block
from .support.test_vectors import (AESExample, DblExample)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

class TestUtil(unittest.TestCase):
    def test_dbl(self):
        for ex in DblExample.load():
            block = Block(ex.input)
            block.dbl()
            self.assertEqual(block.data, ex.output)

    def test_encrypt(self):
        for ex in AESExample.load():
            cipher = Cipher(
                algorithms.AES(ex.key),
                modes.ECB(),
                default_backend()
            )

            block = Block(ex.src)
            block.encrypt(cipher)
            self.assertEqual(block.data, ex.dst)
