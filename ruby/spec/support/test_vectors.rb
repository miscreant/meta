# encoding: binary
# frozen_string_literal: true

require "tjson"

# Error parsing the example file
ParseError = Class.new(StandardError)

class Miscreant::Internals::AES::BlockCipher::Example
  attr_reader :key, :src, :dst

  # Default file to load examples from
  DEFAULT_EXAMPLES = File.expand_path("../../../../vectors/aes.tjson", __FILE__)

  def self.load_file(filename = DEFAULT_EXAMPLES)
    examples = TJSON.load_file(filename).fetch("examples")
    raise ParseError, "expected a toplevel array of examples" unless examples.is_a?(Array)

    examples.map { |example| new(example) }
  end

  def initialize(attrs)
    @key = attrs.fetch("key")
    @src = attrs.fetch("src")
    @dst = attrs.fetch("dst")
  end
end

class Miscreant::Internals::AES::CTR::Example
  attr_reader :key, :iv, :plaintext, :ciphertext

  # Default file to load examples from
  DEFAULT_EXAMPLES = File.expand_path("../../../../vectors/aes_ctr.tjson", __FILE__)

  def self.load_file(filename = DEFAULT_EXAMPLES)
    examples = TJSON.load_file(filename).fetch("examples")
    raise ParseError, "expected a toplevel array of examples" unless examples.is_a?(Array)

    examples.map { |example| new(example) }
  end

  def initialize(attrs)
    @key = attrs.fetch("key")
    @iv = attrs.fetch("iv")
    @plaintext = attrs.fetch("plaintext")
    @ciphertext = attrs.fetch("ciphertext")
  end
end

class Miscreant::Internals::MAC::CMAC::Example
  attr_reader :key, :message, :tag

  # Default file to load examples from
  DEFAULT_EXAMPLES = File.expand_path("../../../../vectors/aes_cmac.tjson", __FILE__)

  def self.load_file(filename = DEFAULT_EXAMPLES)
    examples = TJSON.load_file(filename).fetch("examples")
    raise ParseError, "expected a toplevel array of examples" unless examples.is_a?(Array)

    examples.map { |example| new(example) }
  end

  def initialize(attrs)
    @key = attrs.fetch("key")
    @message = attrs.fetch("message")
    @tag = attrs.fetch("tag")
  end
end

class Miscreant::Internals::MAC::PMAC::Example
  attr_reader :name, :key, :message, :tag

  # Default file to load examples from
  DEFAULT_EXAMPLES = File.expand_path("../../../../vectors/aes_pmac.tjson", __FILE__)

  def self.load_file(filename = DEFAULT_EXAMPLES)
    examples = TJSON.load_file(filename).fetch("examples")
    raise ParseError, "expected a toplevel array of examples" unless examples.is_a?(Array)

    examples.map { |example| new(example) }
  end

  def initialize(attrs)
    @name = attrs.fetch("name")
    @key = attrs.fetch("key")
    @message = attrs.fetch("message")
    @tag = attrs.fetch("tag")
  end
end

class Miscreant::AES::SIV::Example
  attr_reader :name, :key, :ad, :plaintext, :ciphertext

  # AES-SIV (RFC 5297) examples
  CMAC_EXAMPLES = File.expand_path("../../../../vectors/aes_siv.tjson", __FILE__)

  # AES-PMAC-SIV examples
  PMAC_EXAMPLES = File.expand_path("../../../../vectors/aes_pmac_siv.tjson", __FILE__)

  def self.load_cmac_examples
    load_file(CMAC_EXAMPLES)
  end

  def self.load_pmac_examples
    load_file(PMAC_EXAMPLES)
  end

  def self.load_file(filename = DEFAULT_EXAMPLES)
    examples = TJSON.load_file(filename).fetch("examples")
    raise ParseError, "expected a toplevel array of examples" unless examples.is_a?(Array)

    examples.map { |example| new(example) }
  end

  def initialize(attrs)
    @name = attrs.fetch("name")
    @key = attrs.fetch("key")
    @ad = attrs.fetch("ad")
    @plaintext = attrs.fetch("plaintext")
    @ciphertext = attrs.fetch("ciphertext")
  end
end

class Miscreant::AEAD::Example
  attr_reader :name, :alg, :key, :ad, :nonce, :plaintext, :ciphertext

  # Default file to load examples from
  DEFAULT_EXAMPLES = File.expand_path("../../../../vectors/aes_siv_aead.tjson", __FILE__)

  def self.load_file(filename = DEFAULT_EXAMPLES)
    examples = TJSON.load_file(filename).fetch("examples")
    raise ParseError, "expected a toplevel array of examples" unless examples.is_a?(Array)

    examples.map { |example| new(example) }
  end

  def initialize(attrs)
    @name = attrs.fetch("name")
    @alg = attrs.fetch("alg")
    @key = attrs.fetch("key")
    @ad = attrs.fetch("ad")
    @nonce = attrs.fetch("nonce")
    @plaintext = attrs.fetch("plaintext")
    @ciphertext = attrs.fetch("ciphertext")
  end
end

class DblExample
  attr_reader :input, :output

  # Default file to load examples from
  DEFAULT_EXAMPLES = File.expand_path("../../../../vectors/dbl.tjson", __FILE__)

  def self.load_file(filename = DEFAULT_EXAMPLES)
    examples = TJSON.load_file(filename).fetch("examples")
    raise ParseError, "expected a toplevel array of examples" unless examples.is_a?(Array)

    examples.map { |example| new(example) }
  end

  def initialize(attrs)
    @input = attrs.fetch("input")
    @output = attrs.fetch("output")
  end
end
