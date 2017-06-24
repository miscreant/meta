# frozen_string_literal: true

require "spec_helper"
require "support/test_vectors"

RSpec.describe SIVChain do
  it "has a version number" do
    expect(SIVChain::VERSION).not_to be nil
  end
end
