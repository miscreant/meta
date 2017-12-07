extern crate miscreant;
extern crate generic_array;

mod stream_vectors;

use miscreant::{aead, Buffer};
use miscreant::stream::{Aes128PmacSivEncryptor, Aes128PmacSivDecryptor};
use miscreant::stream::{Aes128SivEncryptor, Aes128SivDecryptor};
use miscreant::stream::{Aes256PmacSivEncryptor, Aes256PmacSivDecryptor};
use miscreant::stream::{Aes256SivEncryptor, Aes256SivDecryptor};
use miscreant::stream::{Encryptor, Decryptor};
use stream_vectors::{AesSivStreamExample, Block};

const IV_SIZE: usize = 16;

#[test]
fn aes_siv_stream_examples_seal() {
    for ex in AesSivStreamExample::load_all() {
        match ex.alg.as_ref() {
            "AES-SIV" => {
                match ex.key.len() {
                    32 => test_encryptor(Aes128SivEncryptor::new(&ex.key, &ex.nonce), &ex.blocks),
                    64 => test_encryptor(Aes256SivEncryptor::new(&ex.key, &ex.nonce), &ex.blocks),
                    _ => panic!("unexpected key size: {}", ex.key.len()),
                }
            }
            "AES-PMAC-SIV" => {
                match ex.key.len() {
                    32 => {
                        test_encryptor(Aes128PmacSivEncryptor::new(&ex.key, &ex.nonce), &ex.blocks)
                    }
                    64 => {
                        test_encryptor(Aes256PmacSivEncryptor::new(&ex.key, &ex.nonce), &ex.blocks)
                    }
                    _ => panic!("unexpected key size: {}", ex.key.len()),
                }
            }
            _ => panic!("unexpected algorithm: {}", ex.alg),
        }
    }
}

fn test_encryptor<A: aead::Algorithm>(mut encryptor: Encryptor<A>, blocks: &[Block]) {
    for (i, block) in blocks.iter().enumerate() {
        let mut buffer = Buffer::from(vec![0; IV_SIZE + block.plaintext.len()]);
        buffer.mut_msg_slice().copy_from_slice(&block.plaintext);

        if i < blocks.len() - 1 {
            encryptor.seal_next_in_place(&block.ad, &mut buffer);
            assert_eq!(buffer.as_slice(), block.ciphertext.as_slice());
        } else {
            encryptor.seal_last_in_place(&block.ad, &mut buffer);
            assert_eq!(buffer.as_slice(), block.ciphertext.as_slice());
            return;
        }
    }
}

#[test]
fn aes_siv_stream_examples_open() {
    for ex in AesSivStreamExample::load_all() {
        match ex.alg.as_ref() {
            "AES-SIV" => {
                match ex.key.len() {
                    32 => test_decryptor(Aes128SivDecryptor::new(&ex.key, &ex.nonce), &ex.blocks),
                    64 => test_decryptor(Aes256SivDecryptor::new(&ex.key, &ex.nonce), &ex.blocks),
                    _ => panic!("unexpected key size: {}", ex.key.len()),
                }
            }
            "AES-PMAC-SIV" => {
                match ex.key.len() {
                    32 => {
                        test_decryptor(Aes128PmacSivDecryptor::new(&ex.key, &ex.nonce), &ex.blocks)
                    }
                    64 => {
                        test_decryptor(Aes256PmacSivDecryptor::new(&ex.key, &ex.nonce), &ex.blocks)
                    }
                    _ => panic!("unexpected key size: {}", ex.key.len()),
                }
            }
            _ => panic!("unexpected algorithm: {}", ex.alg),
        }
    }
}

fn test_decryptor<A: aead::Algorithm>(mut decryptor: Decryptor<A>, blocks: &[Block]) {
    for (i, block) in blocks.iter().enumerate() {
        let mut buffer = Buffer::from(block.ciphertext.clone());

        if i < blocks.len() - 1 {
            decryptor
                .open_next_in_place(&block.ad, &mut buffer)
                .expect("decrypt failure");

            assert_eq!(buffer.msg_slice(), block.plaintext.as_slice());
        } else {
            decryptor
                .open_last_in_place(&block.ad, &mut buffer)
                .expect("decrypt failure");

            assert_eq!(buffer.msg_slice(), block.plaintext.as_slice());
            return;
        }
    }
}
