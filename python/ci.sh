#!/bin/bash

set -e

export PATH=$HOME/.local/bin:$PATH
pip install -r requirements.txt
python setup.py test
