extern crate miscreant;

mod siv_vectors;

use miscreant::siv::{Aes128Siv, Aes256Siv, Aes128PmacSiv, Aes256PmacSiv};
use siv_vectors::{AesSivExample, AesPmacSivExample};

#[test]
fn aes_siv_examples_seal() {
    let examples = AesSivExample::load_all();

    for example in examples {
        let ciphertext = match example.key.len() {
            32 => Aes128Siv::new(&example.key).seal(&example.ad, &example.plaintext),
            64 => Aes256Siv::new(&example.key).seal(&example.ad, &example.plaintext),
            _ => panic!("unexpected key size: {}", example.key.len()),
        };

        assert_eq!(ciphertext, example.ciphertext);
    }
}

#[test]
fn aes_siv_examples_open() {
    let examples = AesSivExample::load_all();

    for example in examples {
        let plaintext = match example.key.len() {
            32 => Aes128Siv::new(&example.key).open(&example.ad, &example.ciphertext),
            64 => Aes256Siv::new(&example.key).open(&example.ad, &example.ciphertext),
            _ => panic!("unexpected key size: {}", example.key.len()),
        }.expect("decrypt failure");

        assert_eq!(plaintext, example.plaintext);
    }
}

#[test]
fn aes_pmac_siv_examples_seal() {
    let examples = AesPmacSivExample::load_all();

    for example in examples {
        let ciphertext = match example.key.len() {
            32 => Aes128PmacSiv::new(&example.key).seal(&example.ad, &example.plaintext),
            64 => Aes256PmacSiv::new(&example.key).seal(&example.ad, &example.plaintext),
            _ => panic!("unexpected key size: {}", example.key.len()),
        };

        assert_eq!(ciphertext, example.ciphertext);
    }
}

#[test]
fn aes_pmac_siv_examples_open() {
    let examples = AesPmacSivExample::load_all();

    for example in examples {
        let plaintext = match example.key.len() {
            32 => Aes128PmacSiv::new(&example.key).open(&example.ad, &example.ciphertext),
            64 => Aes256PmacSiv::new(&example.key).open(&example.ad, &example.ciphertext),
            _ => panic!("unexpected key size: {}", example.key.len()),
        }.expect("decrypt failure");

        assert_eq!(plaintext, example.plaintext);
    }
}
