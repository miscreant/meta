# encoding: binary
# frozen_string_literal: true

require "bundler/setup"
require "miscreant"

RSpec.configure(&:disable_monkey_patching!)

# Un-hide the hidden Internals constant so we can test the internals
module Miscreant
  internals = Internals
  remove_const :Internals
  const_set :Internals, internals
end

require "support/test_vectors"
