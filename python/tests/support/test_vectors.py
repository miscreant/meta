"""test_vectors.py: Parse examples from vectors/aes_siv.tjson"""

# TODO: switch to tjson-python instead of hand-rolling a TJSON parser

import binascii
import json
from collections import namedtuple

class AEADExample(namedtuple("AEADExample", ["name", "alg", "key", "ad", "nonce", "plaintext", "ciphertext"])):
    @staticmethod
    def load():
        """Load message examples from vectors/aes_siv_aead.tjson"""
        return AEADExample.load_from_file("../vectors/aes_siv_aead.tjson")

    @staticmethod
    def load_from_file(filename):
        """Load message examples from the specified file"""
        examples_file = open(filename, "r")
        examples_text = examples_file.read()
        examples_file.close()

        examples_tjson = json.loads(examples_text)
        examples = examples_tjson[u"examples:A<O>"]

        result = []
        for example in examples:
            result.append(AEADExample(
                name=example[u"name:s"],
                alg=example[u"alg:s"],
                key=binascii.unhexlify(example[u"key:d16"]),
                ad=binascii.unhexlify(example[u"ad:d16"]),
                nonce=binascii.unhexlify(example[u"nonce:d16"]),
                plaintext=binascii.unhexlify(example[u"plaintext:d16"]),
                ciphertext=binascii.unhexlify(example[u"ciphertext:d16"])
            ))

        return result

class AESExample(namedtuple("AESExample", ["key", "src", "dst"])):
    @staticmethod
    def load():
        """Load message examples from vectors/aes.tjson"""
        return AESExample.load_from_file("../vectors/aes.tjson")

    @staticmethod
    def load_from_file(filename):
        """Load message examples from the specified file"""
        examples_file = open(filename, "r")
        examples_text = examples_file.read()
        examples_file.close()

        examples_tjson = json.loads(examples_text)
        examples = examples_tjson[u"examples:A<O>"]

        result = []
        for example in examples:
            result.append(AESExample(
                key=binascii.unhexlify(example[u"key:d16"]),
                src=binascii.unhexlify(example[u"src:d16"]),
                dst=binascii.unhexlify(example[u"dst:d16"])
            ))

        return result

class PMACExample(namedtuple("PMACExample", ["name", "key", "message", "tag"])):
    @staticmethod
    def load():
        """Load message examples from vectors/aes_pmac.tjson"""
        return PMACExample.load_from_file("../vectors/aes_pmac.tjson")

    @staticmethod
    def load_from_file(filename):
        """Load message examples from the specified file"""
        examples_file = open(filename, "r")
        examples_text = examples_file.read()
        examples_file.close()

        examples_tjson = json.loads(examples_text)
        examples = examples_tjson[u"examples:A<O>"]

        result = []
        for example in examples:
            result.append(PMACExample(
                name=example[u"name:s"],
                key=binascii.unhexlify(example[u"key:d16"]),
                message=binascii.unhexlify(example[u"message:d16"]),
                tag=binascii.unhexlify(example[u"tag:d16"])
            ))

        return result

class SIVExample(namedtuple("SIVExample", ["name", "key", "ad", "plaintext", "ciphertext"])):
    @staticmethod
    def load():
        """Load message examples from vectors/aes_siv.tjson"""
        return SIVExample.load_from_file("../vectors/aes_siv.tjson")

    @staticmethod
    def load_from_file(filename):
        """Load message examples from the specified file"""
        examples_file = open(filename, "r")
        examples_text = examples_file.read()
        examples_file.close()

        examples_tjson = json.loads(examples_text)
        examples = examples_tjson[u"examples:A<O>"]

        result = []
        for example in examples:
            result.append(SIVExample(
                name=example[u"name:s"],
                key=binascii.unhexlify(example[u"key:d16"]),
                ad=[binascii.unhexlify(ad) for ad in example[u"ad:A<d16>"]],
                plaintext=binascii.unhexlify(example[u"plaintext:d16"]),
                ciphertext=binascii.unhexlify(example[u"ciphertext:d16"])
            ))

        return result

class PMACSIVExample(SIVExample):
    @staticmethod
    def load():
        """Load message examples from vectors/aes_pmac_siv.tjson"""
        return SIVExample.load_from_file("../vectors/aes_pmac_siv.tjson")

class STREAMBlock(namedtuple("STREAMBlock", ["ad", "plaintext", "ciphertext"])):
        pass

class STREAMExample(namedtuple("STREAMExample", ["name", "alg", "key", "nonce", "blocks"])):
    @staticmethod
    def load():
        """Load message examples from vectors/aes_siv_stream.tjson"""
        return STREAMExample.load_from_file("../vectors/aes_siv_stream.tjson")

    @staticmethod
    def load_from_file(filename):
        """Load message examples from the specified file"""
        examples_file = open(filename, "r")
        examples_text = examples_file.read()
        examples_file.close()

        examples_tjson = json.loads(examples_text)
        examples = examples_tjson[u"examples:A<O>"]

        result = []
        for example in examples:
            blocks = []
            for b in example[u"blocks:A<O>"]:
                blocks.append(STREAMBlock(
                    ad=binascii.unhexlify(b["ad:d16"]),
                    plaintext=binascii.unhexlify(b["plaintext:d16"]),
                    ciphertext=binascii.unhexlify(b["ciphertext:d16"])
                ))

            result.append(STREAMExample(
                name=example[u"name:s"],
                alg=example[u"alg:s"],
                key=binascii.unhexlify(example[u"key:d16"]),
                nonce=binascii.unhexlify(example[u"nonce:d16"]),
                blocks=blocks,
            ))

        return result

class DblExample(namedtuple("DblExample", ["input", "output"])):
    @staticmethod
    def load():
        """Load message examples from vectors/dbl.tjson"""
        return DblExample.load_from_file("../vectors/dbl.tjson")

    @staticmethod
    def load_from_file(filename):
        """Load message examples from the specified file"""
        examples_file = open(filename, "r")
        examples_text = examples_file.read()
        examples_file.close()

        examples_tjson = json.loads(examples_text)
        examples = examples_tjson[u"examples:A<O>"]

        result = []
        for example in examples:
            result.append(DblExample(
                input=binascii.unhexlify(example[u"input:d16"]),
                output=binascii.unhexlify(example[u"output:d16"])
            ))

        return result
