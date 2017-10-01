#!/usr/bin/env python

"""
test_aead
----------

Tests for the `miscreant.aead` module.
"""

import unittest

from miscreant.aead import AEAD

from .support.test_vectors import AEADExample

class TestAEAD(unittest.TestCase):
    """Tests for the AEAD class"""
    def test_generate_key(self):
        """Ensure we can generate random keys with the right default size"""
        key = AEAD.generate_key()
        self.assertEqual(len(key), 32)

    def test_generate_key(self):
        """Ensure we can generate random nonces with the right default size"""
        nonce = AEAD.generate_nonce()
        self.assertEqual(len(nonce), 16)

    def test_seal(self):
        """Ensure seal passes all AES-(PMAC-)SIV AEAD test vectors"""
        for ex in AEADExample.load():
            aead = AEAD(ex.alg, ex.key)
            ciphertext = aead.seal(ex.plaintext, nonce=ex.nonce, associated_data=ex.ad)
            self.assertEqual(ciphertext, ex.ciphertext)

    def test_open(self):
        """Ensure open passes all AES-SIV test vectors"""
        for ex in AEADExample.load():
            aead = AEAD(ex.alg, ex.key)
            plaintext = aead.open(ex.ciphertext, nonce=ex.nonce, associated_data=ex.ad)
            self.assertEqual(plaintext, ex.plaintext)
