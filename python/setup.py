#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name="miscreant",
    version="0.1.0",
    description="Misuse-resistant authenticated symmetric encryption",
    long_description="Misuse resistant symmetric encryption using the AES-SIV (RFC 5297) and CHAIN/STREAM constructions",
    author="Tony Arcieri",
    author_email="bascule@gmail.com",
    url="https://github.com/miscreant/miscreant/tree/master/python/",
    packages=["miscreant"],
    package_dir={"miscreant": "miscreant"},
    include_package_data=True,
    install_requires=["cryptography>=2.0"],
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
