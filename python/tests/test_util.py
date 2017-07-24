#!/usr/bin/env python

"""
test_util
----------

Tests for the `miscreant.util` module.
"""

import unittest

from miscreant.util import dbl

from .support.test_vectors import DblExample

class TestUtil(unittest.TestCase):
    def test_dbl(self):
        for ex in DblExample.load():
            self.assertEqual(dbl(ex.input), ex.output)
