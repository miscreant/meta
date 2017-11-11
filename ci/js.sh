#!/bin/bash

set -e

cd js
yarn global add typescript prettier tslint mocha
yarn install
yarn test
prettier --list-different "./**/*.ts"
tslint -c tslint.json "src/**/*.ts"

