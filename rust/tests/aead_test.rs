extern crate miscreant;

mod aead_vectors;

use aead_vectors::AesSivAeadExample;
use miscreant::aead::{Aes128Siv, Aes256Siv, Aes128PmacSiv, Aes256PmacSiv, Algorithm};

const IV_SIZE: usize = 16;

#[test]
fn aes_siv_aead_examples_seal() {
    let examples = AesSivAeadExample::load_all();

    for example in examples {
        let mut buffer = vec![0; example.plaintext.len() + IV_SIZE];
        buffer[IV_SIZE..].copy_from_slice(&example.plaintext);

        match example.alg.as_ref() {
            "AES-SIV" => {
                match example.key.len() {
                    32 => {
                        let mut aead = Aes128Siv::new(&example.key);
                        aead.seal_in_place(&example.nonce, &example.ad, &mut buffer);
                    }
                    64 => {
                        let mut aead = Aes256Siv::new(&example.key);
                        aead.seal_in_place(&example.nonce, &example.ad, &mut buffer);
                    }
                    _ => panic!("unexpected key size: {}", example.key.len()),
                }
            }
            "AES-PMAC-SIV" => {
                match example.key.len() {
                    32 => {
                        let mut aead = Aes128PmacSiv::new(&example.key);
                        aead.seal_in_place(&example.nonce, &example.ad, &mut buffer);
                    }
                    64 => {
                        let mut aead = Aes256PmacSiv::new(&example.key);
                        aead.seal_in_place(&example.nonce, &example.ad, &mut buffer);
                    }
                    _ => panic!("unexpected key size: {}", example.key.len()),
                }
            }
            _ => panic!("unexpected algorithm: {}", example.alg),
        }

        assert_eq!(buffer, example.ciphertext);
    }
}

#[test]
fn aes_siv_aead_examples_open() {
    let examples = AesSivAeadExample::load_all();

    for example in examples {
        let mut buffer = example.ciphertext.clone();
        let result = match example.alg.as_ref() {
            "AES-SIV" => {
                match example.key.len() {
                    32 => {
                        let mut aead = Aes128Siv::new(&example.key);
                        aead.open_in_place(&example.nonce, &example.ad, &mut buffer)
                            .expect("decrypt")
                    }
                    64 => {
                        let mut aead = Aes256Siv::new(&example.key);
                        aead.open_in_place(&example.nonce, &example.ad, &mut buffer)
                            .expect("decrypt")
                    }
                    _ => panic!("unexpected key size: {}", example.key.len()),
                }
            }
            "AES-PMAC-SIV" => {
                match example.key.len() {
                    32 => {
                        let mut aead = Aes128PmacSiv::new(&example.key);
                        aead.open_in_place(&example.nonce, &example.ad, &mut buffer)
                            .expect("decrypt")
                    }
                    64 => {
                        let mut aead = Aes256PmacSiv::new(&example.key);
                        aead.open_in_place(&example.nonce, &example.ad, &mut buffer)
                            .expect("decrypt")
                    }
                    _ => panic!("unexpected key size: {}", example.key.len()),
                }
            }
            _ => panic!("unexpected algorithm: {}", example.alg),
        };

        assert_eq!(result, example.plaintext.as_slice());
    }
}
