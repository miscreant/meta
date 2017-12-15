#!/bin/bash

set -e

yarn global add typescript typescript-formatter tslint mocha
yarn install
yarn test

# TODO: presently getting "command not found" errors for anything installed
# via "yarn global".
# tsfmt --verify $(find {src,test} -name "*.ts")
# tslint -c tslint.json "src/**/*.ts"
