# encoding: binary
# frozen_string_literal: true

RSpec.describe Miscreant::STREAM do
  let(:example_alg)   { "AES-SIV" }
  let(:example_key)   { "\x01".b * 32 }
  let(:example_nonce) { "\x01".b * 8 }
  let(:example_ad)    { "Who knows the exact location? Only WW This was his last message" }

  let(:example_plaintext)  { "Thirty eight degrees fifty seven minutes six point five seconds north" }
  let(:example_ciphertext) { encryptor.seal(example_plaintext, ad: example_ad, last_block: true) }

  let(:test_vectors) { described_class::Example.load_file }

  subject(:encryptor) { described_class::Encryptor.new(example_alg, example_key, example_nonce) }
  subject(:decryptor) { described_class::Decryptor.new(example_alg, example_key, example_nonce) }

  context "Encryptor" do
    describe "seal" do
      it "passes all STREAM test vectors" do
        test_vectors.each do |ex|
          encryptor = described_class::Encryptor.new(ex.alg, ex.key, ex.nonce)

          ex.blocks.each_with_index do |block, i|
            ciphertext = encryptor.seal(block.plaintext, ad: block.ad, last_block: i + 1 == ex.blocks.size)
            expect(ciphertext).to eq(block.ciphertext)
          end
        end
      end

      it "raises Miscreant::STREAM::FinishedError if used after finished" do
        encryptor.seal(example_plaintext, ad: example_ad, last_block: true)

        expect do
          encryptor.seal(example_plaintext, ad: example_ad, last_block: true)
        end.to raise_error(Miscreant::STREAM::FinishedError)
      end
    end
  end

  context "Decryptor" do
    describe "open" do
      it "passes all STREAM test vectors" do
        test_vectors.each do |ex|
          decryptor = described_class::Decryptor.new(ex.alg, ex.key, ex.nonce)

          ex.blocks.each_with_index do |block, i|
            plaintext = decryptor.open(block.ciphertext, ad: block.ad, last_block: i + 1 == ex.blocks.size)
            expect(plaintext).to eq(block.plaintext)
          end
        end
      end

      it "raises Miscreant::STREAM::FinishedError if used after finished" do
        decryptor.open(example_ciphertext, ad: example_ad, last_block: true)

        expect do
          decryptor.open(example_ciphertext, ad: example_ad, last_block: true)
        end.to raise_error(Miscreant::STREAM::FinishedError)
      end
    end
  end
end
