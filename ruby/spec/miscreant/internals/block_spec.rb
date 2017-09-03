# encoding: binary
# frozen_string_literal: true

RSpec.describe Miscreant::Internals::Block do
  describe "dbl" do
    let(:test_vectors) { DblExample.load_file }

    it "passes all test vectors" do
      test_vectors.each do |ex|
        block = described_class.new(ex.input)
        block.dbl
        expect(block.data).to eq(ex.output)
      end
    end
  end
end
