#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

requirements = []
test_requirements = []

setup(
    name="sivchain",
    version="0.0.0",
    description="AES-SIV and CHAIN symmetric encryption",
    long_description="Advanced symmetric encryption using the AES-SIV (RFC 5297) and CHAIN constructions",
    author="Tony Arcieri",
    author_email="bascule@gmail.com",
    url="https://github.com/zcred/sivchain/tree/master/python/",
    packages=["sivchain"],
    package_dir={"sivchain": "sivchain"},
    include_package_data=True,
    install_requires=[],
    license="MIT license",
    zip_safe=False,
    keywords=["cryptography", "encryption", "security", "streaming"],
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
    ],
    test_suite="tests",
    tests_require=[]
)
