# frozen_string_literal: true

RSpec.describe Miscreant::Internals::Util do
  describe "dbl" do
    let(:test_vectors) { described_class::DblExample.load_file }

    it "passes all test vectors" do
      test_vectors.each do |ex|
        result = described_class.dbl(ex.input)
        expect(result).to eq(ex.output)
      end
    end
  end
end
