# encoding: binary
# frozen_string_literal: true

RSpec.describe Miscreant::AEAD do
  let(:example_alg)   { "AES-SIV" }
  let(:example_key)   { "\x01".b * 32 }
  let(:example_nonce) { "\x01".b * 32 }
  let(:example_ad)    { "INVALID".b }

  describe "inspect" do
    it "does not contain instance variable values" do
      aead = described_class.new(example_alg, example_key)
      expect(aead.inspect).to match(/\A#<#{described_class}:0[xX][0-9a-fA-F]+>\z/)
    end
  end

  context "AES-SIV AEAD interface" do
    let(:test_vectors) { described_class::Example.load_file }

    describe "seal" do
      it "passes all AES-SIV test vectors" do
        test_vectors.each do |ex|
          aead = described_class.new(ex.alg, ex.key)
          ciphertext = aead.seal(ex.plaintext, nonce: ex.nonce, ad: ex.ad)
          expect(ciphertext).to eq(ex.ciphertext)
        end
      end
    end

    describe "open" do
      it "passes all AES-SIV test vectors" do
        test_vectors.each do |ex|
          aead = described_class.new(ex.alg, ex.key)
          plaintext = aead.open(ex.ciphertext, nonce: ex.nonce, ad: ex.ad)
          expect(plaintext).to eq(ex.plaintext)
        end
      end

      it "should raise IntegrityError if wrong key is given" do
        test_vectors.each do |ex|
          aead = described_class.new(ex.alg, example_key)
          expect do
            aead.open(ex.ciphertext, nonce: ex.nonce, ad: ex.ad)
          end.to raise_error(Miscreant::IntegrityError)
        end
      end

      it "should raise IntegrityError if wrong associated data is given" do
        test_vectors.each do |ex|
          aead = described_class.new(ex.alg, ex.key)
          expect do
            aead.open(ex.ciphertext, nonce: example_nonce, ad: example_ad)
          end.to raise_error(Miscreant::IntegrityError)
        end
      end
    end
  end
end
