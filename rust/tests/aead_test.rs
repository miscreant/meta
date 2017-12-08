extern crate miscreant;

mod aead_vectors;

use aead_vectors::AesSivAeadExample;
use miscreant::aead::{Aes128Siv, Aes256Siv, Aes128PmacSiv, Aes256PmacSiv, Algorithm};

#[test]
fn aes_siv_aead_examples_seal() {
    let examples = AesSivAeadExample::load_all();

    for example in examples {
        let ciphertext = match example.alg.as_ref() {
            "AES-SIV" => {
                match example.key.len() {
                    32 => {
                        Aes128Siv::new(&example.key).seal(
                            &example.nonce,
                            &example.ad,
                            &example.plaintext,
                        )
                    }
                    64 => {
                        Aes256Siv::new(&example.key).seal(
                            &example.nonce,
                            &example.ad,
                            &example.plaintext,
                        )
                    }
                    _ => panic!("unexpected key size: {}", example.key.len()),
                }
            }
            "AES-PMAC-SIV" => {
                match example.key.len() {
                    32 => {
                        Aes128PmacSiv::new(&example.key).seal(
                            &example.nonce,
                            &example.ad,
                            &example.plaintext,
                        )
                    }
                    64 => {
                        Aes256PmacSiv::new(&example.key).seal(
                            &example.nonce,
                            &example.ad,
                            &example.plaintext,
                        )
                    }
                    _ => panic!("unexpected key size: {}", example.key.len()),
                }
            }
            _ => panic!("unexpected algorithm: {}", example.alg),
        };

        assert_eq!(ciphertext, example.ciphertext);
    }
}

#[test]
fn aes_siv_aead_examples_open() {
    let examples = AesSivAeadExample::load_all();

    for example in examples {
        let plaintext = match example.alg.as_ref() {
            "AES-SIV" => {
                match example.key.len() {
                    32 => {
                        Aes128Siv::new(&example.key).open(
                            &example.nonce,
                            &example.ad,
                            &example.ciphertext,
                        )
                    }
                    64 => {
                        Aes256Siv::new(&example.key).open(
                            &example.nonce,
                            &example.ad,
                            &example.ciphertext,
                        )
                    }
                    _ => panic!("unexpected key size: {}", example.key.len()),
                }
            }
            "AES-PMAC-SIV" => {
                match example.key.len() {
                    32 => {
                        Aes128PmacSiv::new(&example.key).open(
                            &example.nonce,
                            &example.ad,
                            &example.ciphertext,
                        )
                    }
                    64 => {
                        Aes256PmacSiv::new(&example.key).open(
                            &example.nonce,
                            &example.ad,
                            &example.ciphertext,
                        )
                    }
                    _ => panic!("unexpected key size: {}", example.key.len()),
                }
            }
            _ => panic!("unexpected algorithm: {}", example.alg),
        }.expect("decrypt failure");

        assert_eq!(plaintext, example.plaintext);
    }
}
