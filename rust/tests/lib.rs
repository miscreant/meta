extern crate miscreant;

use miscreant::{Aes128Siv, Aes256Siv, Aes128PmacSiv, Aes256PmacSiv};

mod test_vectors;
use test_vectors::{AesSivExample, AesPmacSivExample};

const BLOCK_SIZE: usize = 16;

#[test]
fn aes_siv_examples_seal() {
    let examples = AesSivExample::load_all();

    for example in examples {
        let len = example.plaintext.len();
        let mut buffer = vec![0; len + BLOCK_SIZE];
        buffer[BLOCK_SIZE..].copy_from_slice(&example.plaintext);

        match example.key.len() {
            32 => {
                let mut siv = Aes128Siv::new(&example.key);
                siv.seal_in_place(&example.ad, &mut buffer);
            }
            64 => {
                let mut siv = Aes256Siv::new(&example.key);
                siv.seal_in_place(&example.ad, &mut buffer);
            }
            _ => panic!("unexpected key size: {}", example.key.len()),
        };

        assert_eq!(buffer, example.ciphertext);
    }
}

#[test]
fn aes_siv_examples_open() {
    let examples = AesSivExample::load_all();

    for example in examples {
        let mut buffer = example.ciphertext.clone();

        let plaintext = match example.key.len() {
            32 => {
                let mut siv = Aes128Siv::new(&example.key);
                siv.open_in_place(&example.ad, &mut buffer)
            }
            64 => {
                let mut siv = Aes256Siv::new(&example.key);
                siv.open_in_place(&example.ad, &mut buffer)
            }
            _ => panic!("unexpected key size: {}", example.key.len()),
        }.expect("successful decrypt");

        assert_eq!(plaintext, &example.plaintext[..]);
    }
}

#[test]
fn aes_pmac_siv_examples_seal() {
    let examples = AesPmacSivExample::load_all();

    for example in examples {
        let len = example.plaintext.len();
        let mut buffer = vec![0; len + BLOCK_SIZE];
        buffer[BLOCK_SIZE..].copy_from_slice(&example.plaintext);

        match example.key.len() {
            32 => {
                let mut siv = Aes128PmacSiv::new(&example.key);
                siv.seal_in_place(&example.ad, &mut buffer);
            }
            64 => {
                let mut siv = Aes256PmacSiv::new(&example.key);
                siv.seal_in_place(&example.ad, &mut buffer);
            }
            _ => panic!("unexpected key size: {}", example.key.len()),
        };

        assert_eq!(buffer, example.ciphertext);
    }
}

#[test]
fn aes_pmac_siv_examples_open() {
    let examples = AesPmacSivExample::load_all();

    for example in examples {
        let mut buffer = example.ciphertext.clone();

        let plaintext = match example.key.len() {
            32 => {
                let mut siv = Aes128PmacSiv::new(&example.key);
                siv.open_in_place(&example.ad, &mut buffer)
            }
            64 => {
                let mut siv = Aes256PmacSiv::new(&example.key);
                siv.open_in_place(&example.ad, &mut buffer)
            }
            _ => panic!("unexpected key size: {}", example.key.len()),
        }.expect("successful decrypt");

        assert_eq!(plaintext, &example.plaintext[..]);
    }
}
