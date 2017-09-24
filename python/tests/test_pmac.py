#!/usr/bin/env python

"""
test_aes_pmac
----------

Tests for the `miscreant.mac.pmac` module.
"""

import unittest

from miscreant.mac.pmac import PMAC
from miscreant.exceptions import IntegrityError

from .support.test_vectors import PMACExample

from cryptography.hazmat.primitives.ciphers import algorithms

class TestPMAC(unittest.TestCase):
    # Ensure seal passes all AES-PMAC test vectors
    def test_pmac(self):
        for ex in PMACExample.load():
            pmac = PMAC(algorithms.AES(ex.key))
            pmac.update(ex.message)
            self.assertEqual(pmac.finalize(), ex.tag)
