#!/bin/bash

set -e

cd ruby
bundle
bundle exec rake
