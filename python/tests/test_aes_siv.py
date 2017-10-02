#!/usr/bin/env python

"""
test_aes_siv
----------

Tests for the `miscreant.aes.siv` module.
"""

import unittest

from miscreant.aes.siv import SIV
from miscreant.mac.pmac import PMAC
from miscreant.exceptions import IntegrityError

from .support.test_vectors import SIVExample, PMACSIVExample

class TestAesSiv(unittest.TestCase):
    """Tests for the AES-(CMAC)-SIV (RFC 5297) construction"""

    def test_generate_key(self):
        """Ensure we can generate random keys with the right default size"""
        key = SIV.generate_key()
        self.assertEqual(len(key), 32)

    def test_seal(self):
        """Ensure the 'seal' method passes all AES-SIV test vectors"""
        for ex in SIVExample.load():
            siv = SIV(ex.key)
            ciphertext = siv.seal(ex.plaintext, ex.ad)
            self.assertEqual(ciphertext, ex.ciphertext)

    def test_open(self):
        """Ensure the 'open' method passes all AES-SIV test vectors"""
        for ex in SIVExample.load():
            siv = SIV(ex.key)
            plaintext = siv.open(ex.ciphertext, ex.ad)
            self.assertEqual(plaintext, ex.plaintext)

    def test_open_with_wrong_key(self):
        """Ensure 'open' raises IntegrityError if wrong key is given"""
        bad_key = b"\x01" * 32
        siv = SIV(bad_key)

        for ex in SIVExample.load():
            with self.assertRaises(IntegrityError):
                siv.open(ex.ciphertext, ex.ad)

    def test_open_with_wrong_associated_data(self):
        """Ensure 'open' raises IntegrityError if wrong associated data is given"""
        bad_ad = [b"INVALID"]
        for ex in SIVExample.load():
            siv = SIV(ex.key)
            with self.assertRaises(IntegrityError):
                siv.open(ex.ciphertext, bad_ad)

class TestAesPmacSiv(unittest.TestCase):
    """Tests for the AES-PMAC-SIV construction"""

    def test_seal(self):
        """Ensure the 'seal' method passes all AES-SIV test vectors"""
        for ex in PMACSIVExample.load():
            siv = SIV(ex.key, PMAC)
            ciphertext = siv.seal(ex.plaintext, ex.ad)
            self.assertEqual(ciphertext, ex.ciphertext)

    def test_open(self):
        """Ensure the 'open' passes all AES-SIV test vectors"""
        for ex in PMACSIVExample.load():
            siv = SIV(ex.key, PMAC)
            plaintext = siv.open(ex.ciphertext, ex.ad)
            self.assertEqual(plaintext, ex.plaintext)
