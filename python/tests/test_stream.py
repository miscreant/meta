#!/usr/bin/env python

"""
test_stream
----------

Tests for the `miscreant.stream` module.
"""

import unittest

from miscreant.stream import (Encryptor, Decryptor)

from .support.test_vectors import STREAMExample

class TestSTREAM(unittest.TestCase):
    def test_seal(self):
        """Ensure seal passes all AES-(PMAC-)SIV STREAM test vectors"""
        for ex in STREAMExample.load():
            encryptor = Encryptor(ex.alg, ex.key, ex.nonce)
            for i, block in enumerate(ex.blocks):
                ciphertext = encryptor.seal(block.plaintext, associated_data=block.ad, last_block=i+1 == len(ex.blocks))
                self.assertEqual(ciphertext, block.ciphertext)

    def test_open(self):
        """Ensure open passes all AES-(PMAC-)SIV STREAM test vectors"""
        for ex in STREAMExample.load():
            decryptor = Decryptor(ex.alg, ex.key, ex.nonce)
            for i, block in enumerate(ex.blocks):
                plaintext = decryptor.open(block.ciphertext, associated_data=block.ad, last_block=i+1 == len(ex.blocks))
                self.assertEqual(plaintext, block.plaintext)
