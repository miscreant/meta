# encoding: binary
# frozen_string_literal: true

RSpec.describe Miscreant::Internals::MAC::CMAC do
  let(:example_key) { ("\x01" * 16).b }

  describe "inspect" do
    it "does not contain instance variable values" do
      cmac = described_class.new(example_key)
      expect(cmac.inspect).to match(/\A#<#{described_class}:0[xX][0-9a-fA-F]+>\z/)
    end
  end

  context "AES" do
    describe "digest" do
      it "passes all AES-CMAC test vectors" do
        described_class::Example.load_file.each do |ex|
          cmac = described_class.new(ex.key)
          output = cmac.digest(ex.message)
          expect(output).to eq(ex.tag)
        end
      end
    end
  end
end
