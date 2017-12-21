# encoding: binary
# frozen_string_literal: true

RSpec.describe Miscreant::STREAM do
  let(:test_vectors) { Miscreant::STREAM::Example.load_file }

  context "Encryptor" do
    describe "seal" do
      it "passes all STREAM test vectors" do
        test_vectors.each do |ex|
          stream = Miscreant::STREAM::Encryptor.new(ex.alg, ex.key, ex.nonce)

          ex.blocks.each_with_index do |block, i|
            ciphertext = stream.seal(block.plaintext, ad: block.ad, last_block: i + 1 == ex.blocks.size)
            expect(ciphertext).to eq(block.ciphertext)
          end
        end
      end
    end
  end

  context "Decryptor" do
    describe "open" do
      it "passes all STREAM test vectors" do
        test_vectors.each do |ex|
          stream = Miscreant::STREAM::Decryptor.new(ex.alg, ex.key, ex.nonce)

          ex.blocks.each_with_index do |block, i|
            plaintext = stream.open(block.ciphertext, ad: block.ad, last_block: i + 1 == ex.blocks.size)
            expect(plaintext).to eq(block.plaintext)
          end
        end
      end
    end
  end
end
