# encoding: binary
# frozen_string_literal: true

RSpec.describe Miscreant::SIV do
  let(:example_key) { "\x01".b * 32 }
  let(:example_ad) { ["INVALID".b] }

  describe "inspect" do
    it "does not contain instance variable values" do
      cmac = described_class.new(example_key)
      expect(cmac.inspect).to match(/\A#<#{described_class}:0[xX][0-9a-fA-F]+>\z/)
    end
  end

  context "AES-SIV (CMAC)" do
    let(:test_vectors) { described_class::Example.load_cmac_examples }

    describe "seal" do
      it "passes all AES-SIV test vectors" do
        test_vectors.each do |ex|
          siv = described_class.new(ex.key)
          ciphertext = siv.seal(ex.plaintext, ex.ad)
          expect(ciphertext).to eq(ex.ciphertext)
        end
      end
    end

    describe "open" do
      it "passes all AES-SIV test vectors" do
        test_vectors.each do |ex|
          siv = described_class.new(ex.key)
          plaintext = siv.open(ex.ciphertext, ex.ad)
          expect(plaintext).to eq(ex.plaintext)
        end
      end

      it "should raise IntegrityError if wrong key is given" do
        test_vectors.each do |ex|
          siv = described_class.new(example_key)
          expect { siv.open(ex.ciphertext, ex.ad) }.to raise_error(Miscreant::IntegrityError)
        end
      end

      it "should raise IntegrityError if wrong associated data is given" do
        test_vectors.each do |ex|
          siv = described_class.new(ex.key)
          expect { siv.open(ex.ciphertext, example_ad) }.to raise_error(Miscreant::IntegrityError)
        end
      end
    end
  end

  context "AES-PMAC-SIV" do
    let(:test_vectors) { described_class::Example.load_pmac_examples }

    describe "seal" do
      it "passes all AES-PMAC-SIV test vectors" do
        test_vectors.each do |ex|
          siv = described_class.new(ex.key, :PMAC)
          ciphertext = siv.seal(ex.plaintext, ex.ad)
          expect(ciphertext).to eq(ex.ciphertext)
        end
      end
    end

    describe "open" do
      it "passes all AES-PMAC-SIV test vectors" do
        test_vectors.each do |ex|
          siv = described_class.new(ex.key, :PMAC)
          plaintext = siv.open(ex.ciphertext, ex.ad)
          expect(plaintext).to eq(ex.plaintext)
        end
      end

      it "should raise IntegrityError if wrong key is given" do
        test_vectors.each do |ex|
          siv = described_class.new(example_key, :PMAC)
          expect { siv.open(ex.ciphertext, ex.ad) }.to raise_error(Miscreant::IntegrityError)
        end
      end

      it "should raise IntegrityError if wrong associated data is given" do
        test_vectors.each do |ex|
          siv = described_class.new(ex.key, :PMAC)
          expect { siv.open(ex.ciphertext, example_ad) }.to raise_error(Miscreant::IntegrityError)
        end
      end
    end
  end
end
