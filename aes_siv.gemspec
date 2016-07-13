# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'aes_siv/version'

Gem::Specification.new do |spec|
  spec.name          = "aes_siv"
  spec.version       = AES_SIV::VERSION
  spec.authors       = ["John Downey"]
  spec.email         = ["jdowney@gmail.com"]

  spec.summary       = %q{AES SIV}
  spec.homepage      = "TODO: Put your gem's website or public repo URL here."
  spec.license       = "MIT"

  spec.files         = Dir.glob("{lib,test}/**.rb") + %w[README.md LICENSE.txt CODE_OF_CONDUCT.md Rakefile]
  spec.require_paths = ["lib"]

  spec.add_dependency "cmac", "~> 0.3"
  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake", "10.5.0"
  spec.add_development_dependency "minitest", "5.8.4"
end
