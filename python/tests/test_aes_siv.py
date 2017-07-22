#!/usr/bin/env python

"""
test_aes_siv
----------

Tests for the `sivchain.aes.siv` module.
"""

import unittest

from sivchain.aes.siv import SIV
from sivchain.exceptions import IntegrityError

from .support.test_vectors import SIVExample

class TestAesSiv(unittest.TestCase):
    # Ensure we can generate random keys with the right default size
    def test_generate_key(self):
        key = SIV.generate_key()
        self.assertEqual(len(key), 32)

    # Ensure seal passes all AES-SIV test vectors
    def test_seal(self):
        for ex in SIVExample.load():
            siv = SIV(ex.key)
            ciphertext = siv.seal(ex.plaintext, ex.ad)
            self.assertEqual(ciphertext, ex.output)

    # Ensure open passes all AES-SIV test vectors
    def test_open(self):
        for ex in SIVExample.load():
            siv = SIV(ex.key)
            plaintext = siv.open(ex.output, ex.ad)
            self.assertEqual(plaintext, ex.plaintext)

    # Ensure open raises IntegrityError if wrong key is given
    def test_open_with_wrong_key(self):
        bad_key = b"\x01" * 32
        siv = SIV(bad_key)

        for ex in SIVExample.load():
            with self.assertRaises(IntegrityError):
                siv.open(ex.output, ex.ad)

    # Ensure open raises IntegrityError if wrong associated data is given
    def test_open_with_wrong_associated_data(self):
        bad_ad = [b"INVALID"]
        for ex in SIVExample.load():
            siv = SIV(ex.key)
            with self.assertRaises(IntegrityError):
                siv.open(ex.output, bad_ad)
