# frozen_string_literal: true

RSpec.describe SIVChain::AES::SIV do
  let(:example_key) { "\x01".b * 32 }

  describe "inspect" do
    it "does not contain instance variable values" do
      cmac = described_class.new(example_key)
      expect(cmac.inspect).to match(/\A#<SIVChain::AES::SIV:0[xX][0-9a-fA-F]+>\z/)
    end
  end

  describe "encrypt" do
    it "passes all AES-SIV test vectors" do
      described_class::Example.load_file.each do |ex|
        siv = described_class.new(ex.key)
        ciphertext = siv.encrypt(ex.plaintext, ex.ad)
        expect(ciphertext).to eq(ex.output)
      end
    end
  end

  describe "decrypt" do
    it "passes all AES-SIV test vectors" do
      described_class::Example.load_file.each do |ex|
        siv = described_class.new(ex.key)
        plaintext = siv.decrypt(ex.output, ex.ad)
        expect(plaintext).to eq(ex.plaintext)
      end
    end
  end
end
