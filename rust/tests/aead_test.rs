extern crate miscreant;

mod aead_vectors;

use aead_vectors::AesSivAeadExample;
use miscreant::aead::{Aes128SivAead, Aes256SivAead, Aes128PmacSivAead, Aes256PmacSivAead,
                      Algorithm};

const IV_SIZE: usize = 16;

#[test]
fn aes_siv_aead_examples_seal() {
    let examples = AesSivAeadExample::load_all();

    for example in examples {
        let len = example.plaintext.len();
        let mut buffer = vec![0; len + IV_SIZE];
        buffer[IV_SIZE..].copy_from_slice(&example.plaintext);

        match example.alg.as_ref() {
            "AES-SIV" => {
                match example.key.len() {
                    32 => {
                        let mut aead = Aes128SivAead::new(&example.key);
                        aead.seal_in_place(&example.nonce, &example.ad, &mut buffer);
                    }
                    64 => {
                        let mut aead = Aes256SivAead::new(&example.key);
                        aead.seal_in_place(&example.nonce, &example.ad, &mut buffer);
                    }
                    _ => panic!("unexpected key size: {}", example.key.len()),
                }
            }
            "AES-PMAC-SIV" => {
                match example.key.len() {
                    32 => {
                        let mut aead = Aes128PmacSivAead::new(&example.key);
                        aead.seal_in_place(&example.nonce, &example.ad, &mut buffer);
                    }
                    64 => {
                        let mut aead = Aes256PmacSivAead::new(&example.key);
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
