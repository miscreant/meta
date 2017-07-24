# frozen_string_literal: true

RSpec.describe Miscreant::AES::CMAC do
  let(:example_key) { ("\x01" * 16).b }

  describe "inspect" do
    it "does not contain instance variable values" do
      cmac = described_class.new(example_key)
      expect(cmac.inspect).to match(/\A#<Miscreant::AES::CMAC:0[xX][0-9a-fA-F]+>\z/)
    end
  end

  describe "digest" do
    it "passes all AES-CMAC test vectors" do
      described_class::Example.load_file.each do |ex|
        cmac = described_class.new(ex.key)
        output = cmac.digest(ex.input)
        expect(output).to eq(ex.result)
      end
    end
  end
end
