#!/bin/bash --login

set -e

if [ -z "$SUITE" ]; then
    for SUITE in go js python ruby rust; do
        echo "*** Running test suite: $SUITE"
        SUITE=$SUITE ./$0
    done
fi

case $SUITE in
go)
    cd go
    go vet ./...
    go test -v ./...
    ;;
js)
    cd js
    yarn global add typescript typescript-formatter tslint mocha
    yarn install
    yarn test
    tsfmt --verify $(find {src,test} -name "*.ts")
    tslint -c tslint.json "src/**/*.ts"
    ;;
python)
    cd python
    export PATH=$HOME/.local/bin:$PATH
    pip install -r requirements.txt
    py.test
    ;;
ruby)
    cd ruby
    bundle
    bundle exec rake
    ;;
rust)
    cd rust
    cargo test
    ;;
*)
    echo "*** ERROR: Unknown test suite: '$SUITE'"
    exit 1
    ;;
esac

echo "Success!"
exit 0
