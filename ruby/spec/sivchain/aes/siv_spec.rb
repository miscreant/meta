# frozen_string_literal: true

RSpec.describe SIVChain::AES::SIV do
  let(:example_key) { "\x01".b * 32 }
  let(:example_ad) { ["XXX"] }
  let(:test_vectors) { described_class::Example.load_file }

  describe "inspect" do
    it "does not contain instance variable values" do
      cmac = described_class.new(example_key)
      expect(cmac.inspect).to match(/\A#<SIVChain::AES::SIV:0[xX][0-9a-fA-F]+>\z/)
    end
  end

  describe "encrypt" do
    it "passes all AES-SIV test vectors" do
      test_vectors.each do |ex|
        siv = described_class.new(ex.key)
        ciphertext = siv.encrypt(ex.plaintext, ex.ad)
        expect(ciphertext).to eq(ex.output)
      end
    end
  end

  describe "decrypt" do
    it "passes all AES-SIV test vectors" do
      test_vectors.each do |ex|
        siv = described_class.new(ex.key)
        plaintext = siv.decrypt(ex.output, ex.ad)
        expect(plaintext).to eq(ex.plaintext)
      end
    end

    it "should raise IntegrityError if wrong key is given" do
      test_vectors.each do |ex|
        siv = described_class.new(example_key)
        expect { siv.decrypt(ex.output, ex.ad) }.to raise_error(SIVChain::IntegrityError)
      end
    end

    it "should raise IntegrityError if wrong associated data is given" do
      test_vectors.each do |ex|
        siv = described_class.new(ex.key)
        expect { siv.decrypt(ex.output, example_ad) }.to raise_error(SIVChain::IntegrityError)
      end
    end
  end
end
