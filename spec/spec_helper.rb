require 'cmac'

TestKey = "\x01" * 16

RSpec.configure do |config|
  config.order = 'random'
end

def test_vectors
  test_file = File.expand_path('../test_vectors.txt', __FILE__)
  test_lines = File.readlines(test_file).map(&:strip).reject(&:empty?)

  vectors = {}
  test_lines.each_slice(5) do |lines|
    name = lines.shift
    values = lines.inject({}) do |hash, line|
      key, value = line.split('=').map(&:strip)
      value = '' unless value
      value = [value.slice(2..-1)].pack('H*') if value.start_with?('0x')
      hash[key.to_sym] = value
      hash
    end
    vectors[name] = values
  end
  vectors
end
