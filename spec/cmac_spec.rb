require 'spec_helper'

describe CMAC do
  describe 'sign' do
    test_vectors.each do |name, options|
      it "should match the \"#{name}\" test vector" do
        cmac = CMAC.new(options[:Key])
        cmac.sign(options[:Message], options[:Truncate].to_i).should == options[:Tag]
      end
    end

    it 'should give a truncated output if requested' do
      cmac = CMAC.new(TestKey)
      cmac.sign('attack at dawn', 12).length.should == 12
    end

    it 'should raise error if truncation request is greater than 16 bytes' do
      cmac = CMAC.new(TestKey)
      expect do
        cmac.sign('attack at dawn', 17)
      end.to raise_error(CMAC::Exception, 'Tag cannot be greater than maximum (16 bytes)')
    end

    it 'should raise error if truncation request is less than 8 bytes' do
      cmac = CMAC.new(TestKey)
      expect do
        cmac.sign('attack at dawn', 7)
      end.to raise_error(CMAC::Exception, 'Tag cannot be less than minimum (8 bytes)')
    end
  end

  describe 'valid_message?' do
    it 'should be true for matching messages' do
      message = 'attack at dawn'
      cmac = CMAC.new(TestKey)
      tag = cmac.sign(message)
      cmac.should be_valid_message(tag, message)
    end

    it 'should be false for modified messages' do
      cmac = CMAC.new(TestKey)
      tag = cmac.sign('attack at dawn')
      cmac.should_not be_valid_message(tag, 'attack at dusk')
    end
  end
end
