# coding: utf-8
# frozen_string_literal: true

lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "miscreant/version"

Gem::Specification.new do |spec|
  spec.name          = "miscreant"
  spec.authors       = ["Tony Arcieri"]
  spec.email         = ["bascule@gmail.com"]
  spec.summary       = "Misuse-resistant authenticated symmetric encryption"
  spec.description   = <<-DESCRIPTION.strip.gsub(/\s+/, " ")
    Misuse resistant symmetric encryption library providing AES-SIV (RFC 5297),
    AES-PMAC-SIV, and STREAM constructions
  DESCRIPTION

  spec.version       = Miscreant::VERSION
  spec.licenses      = ["MIT"]
  spec.homepage      = "https://github.com/miscreant/miscreant/tree/master/ruby/"
  spec.description   = ""
  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 2.2.2"

  spec.add_development_dependency "bundler", "~> 1.14"
end
