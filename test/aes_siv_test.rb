require 'test_helper'

class AES_SIVTest < Minitest::Test
  def test_valid_key_lengths
    aes_siv = AES_SIV.new("\0" * 32)
    refute_nil aes_siv

    aes_siv = AES_SIV.new("\0" * 48)
    refute_nil aes_siv

    aes_siv = AES_SIV.new("\0" * 64)
    refute_nil aes_siv
  end

  def test_invalid_key_lengths
    assert_raises(ArgumentError) do
      AES_SIV.new("\0" * 52)
    end
  end

  def test_deterministic_authenticated_encryption
    key = ["fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"].pack("H*")
    associated_data = ["101112131415161718191a1b1c1d1e1f2021222324252627"].pack("H*")
    plaintext = ["112233445566778899aabbccddee"].pack("H*")
    ciphertext = ["85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c"].pack("H*")

    aes_siv = AES_SIV.new(key)

    assert_equal ciphertext, aes_siv.encrypt(plaintext, associated_data: associated_data)
  end

  def test_nonce_based_authenticated_encryption
    key = ["7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f"].pack("H*")
    associated_data = []
    associated_data << ["00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"].pack("H*")
    associated_data << ["102030405060708090a0"].pack("H*")
    nonce = ["09f911029d74e35bd84156c5635688c0"].pack("H*")
    plaintext = ["7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"].pack("H*")
    ciphertext = ["7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d"].pack("H*")

    aes_siv = AES_SIV.new(key)

    assert_equal ciphertext, aes_siv.encrypt(plaintext, associated_data: associated_data, nonce: nonce)
  end

  def test_encrypt_and_decrypt_aes128
    key = SecureRandom.random_bytes(32)
    nonce = SecureRandom.random_bytes(16)

    aes_siv = AES_SIV.new(key)
    ciphertext = aes_siv.encrypt("too many secrets", nonce: nonce)

    assert_equal "too many secrets", aes_siv.decrypt(ciphertext, nonce: nonce)
  end

  def test_encrypt_and_decrypt_aes192
    key = SecureRandom.random_bytes(48)
    nonce = SecureRandom.random_bytes(16)

    aes_siv = AES_SIV.new(key)
    ciphertext = aes_siv.encrypt("too many secrets", nonce: nonce)

    assert_equal "too many secrets", aes_siv.decrypt(ciphertext, nonce: nonce)
  end

  def test_encrypt_and_decrypt_aes256
    key = SecureRandom.random_bytes(64)
    nonce = SecureRandom.random_bytes(16)

    aes_siv = AES_SIV.new(key)
    ciphertext = aes_siv.encrypt("too many secrets", nonce: nonce)

    assert_equal "too many secrets", aes_siv.decrypt(ciphertext, nonce: nonce)
  end
end
