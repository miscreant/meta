#!/bin/bash

set -e

cd js
yarn global add typescript typescript-formatter tslint mocha
yarn install
yarn test
tsfmt --verify $(find {src,test} -name "*.ts")
tslint -c tslint.json "src/**/*.ts"

