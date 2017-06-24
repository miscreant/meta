# -*- encoding: utf-8 -*-
$:.unshift File.expand_path('../lib', __FILE__)
require 'cmac/version'

Gem::Specification.new do |s|
  s.name        = 'cmac'
  s.version     = CMAC::VERSION
  s.authors     = ['John Downey']
  s.email       = ['jdowney@gmail.com']
  s.homepage    = 'https://github.com/jtdowney/cmac'
  s.license     = 'MIT'
  s.summary     = %q{Cipher-based Message Authentication Code}
  s.description = %q{A ruby implementation of RFC4493, RFC4494, and RFC4615. CMAC is a message authentication code (MAC) built using AES-128.}

  s.files         = Dir.glob('{lib,spec}/**/*') + %w{README.md LICENSE}
  s.test_files    = Dir.glob('spec/**/*')
  s.require_paths = ['lib']

  s.add_development_dependency 'rake', '10.5.0'
  s.add_development_dependency 'rspec', '3.4.0'
end
