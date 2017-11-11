#!/bin/bash

set -e

cd python
export PATH=$HOME/.local/bin:$PATH
pip install -r requirements.txt
py.test
