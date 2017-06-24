require 'cmac'

TestKey = "\x01" * 16

RSpec.configure do |config|
  config.order = 'random'
end

def test_vectors
  test_file = File.expand_path('../test_vectors.txt', __FILE__)
  test_lines = File.readlines(test_file).map(&:strip).reject(&:empty?)
  test_lines.each_slice(5).reduce({}) do |vectors, lines|
    name = lines.shift
    vector = lines.reduce({}) do |values, line|
      key, value = line.split('=').map(&:strip)
      value ||= ''
      value = [value.slice(2..-1)].pack('H*') if value.start_with?('0x')

      values.merge!(key.to_sym => value)
    end

    vectors.merge!(name => vector)
  end
end
