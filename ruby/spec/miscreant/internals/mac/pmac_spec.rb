# encoding: binary
# frozen_string_literal: true

RSpec.describe Miscreant::Internals::MAC::PMAC do
  let(:example_key) { ("\x01" * 16).b }

  describe "inspect" do
    it "does not contain instance variable values" do
      pmac = described_class.new(example_key)
      expect(pmac.inspect).to match(/\A#<#{described_class}:0[xX][0-9a-fA-F]+>\z/)
    end
  end

  context "AES" do
    describe "digest" do
      it "passes all AES-PMAC test vectors" do
        described_class::Example.load_file.each do |ex|
          pmac = described_class.new(ex.key)
          expect(pmac.digest(ex.message)).to eq(ex.tag)
        end
      end
    end
  end
end
