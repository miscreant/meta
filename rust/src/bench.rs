extern crate ring;

use self::ring::aead;
use siv::{Aes128PmacSiv, Aes128Siv};
use test::Bencher;

// WARNING: Do not ever actually use a key of all zeroes
const KEY_128_BIT: [u8; 16] = [0u8; 16];
const KEY_256_BIT: [u8; 32] = [0u8; 32];

const NONCE: [u8; 12] = [0u8; 12];

//
// AES-SIV benchmarks
//

#[bench]
fn bench_aes_siv_128_encrypt_128_bytes(b: &mut Bencher) {
    let mut siv = Aes128Siv::new(&KEY_256_BIT);

    // 128 bytes input + 16 bytes tag
    let mut buffer = vec![0u8; 144];
    b.bytes = 128;

    b.iter(|| {
        siv.seal_in_place(&[NONCE], &mut buffer);
    });
}

#[bench]
fn bench_aes_siv_128_encrypt_1024_bytes(b: &mut Bencher) {
    let mut siv = Aes128Siv::new(&KEY_256_BIT);

    // 1024 bytes input + 16 bytes tag
    let mut buffer = vec![0u8; 1040];
    b.bytes = 1024;

    b.iter(|| {
        siv.seal_in_place(&[NONCE], &mut buffer);
    });
}

#[bench]
fn bench_aes_siv_128_encrypt_16384_bytes(b: &mut Bencher) {
    let mut siv = Aes128Siv::new(&KEY_256_BIT);

    // 16384 bytes input + 16 bytes tag
    let mut buffer = vec![0u8; 16400];
    b.bytes = 16384;

    b.iter(|| {
        siv.seal_in_place(&[NONCE], &mut buffer);
    });
}

//
// AES-PMAC-SIV benchmarks
//

#[bench]
fn bench_aes_pmac_siv_128_encrypt_128_bytes(b: &mut Bencher) {
    let mut siv = Aes128PmacSiv::new(&KEY_256_BIT);

    // 128 bytes input + 16 bytes tag
    let mut buffer = vec![0u8; 144];
    b.bytes = 128;

    b.iter(|| {
        siv.seal_in_place(&[NONCE], &mut buffer);
    });
}

#[bench]
fn bench_aes_pmac_siv_128_encrypt_1024_bytes(b: &mut Bencher) {
    let mut siv = Aes128PmacSiv::new(&KEY_256_BIT);

    // 1024 bytes input + 16 bytes tag
    let mut buffer = vec![0u8; 1040];
    b.bytes = 1024;

    b.iter(|| {
        siv.seal_in_place(&[NONCE], &mut buffer);
    });
}

#[bench]
fn bench_aes_pmac_siv_128_encrypt_16384_bytes(b: &mut Bencher) {
    let mut siv = Aes128PmacSiv::new(&KEY_256_BIT);

    // 16384 bytes input + 16 bytes tag
    let mut buffer = vec![0u8; 16400];
    b.bytes = 16384;

    b.iter(|| {
        siv.seal_in_place(&[NONCE], &mut buffer);
    });
}

//
// AES-GCM benchmarks for comparison (using *ring*)
//

#[bench]
fn bench_aes_gcm_128_encrypt_128_bytes(b: &mut Bencher) {
    let sealing_key =
        aead::SealingKey::new(&aead::AES_128_GCM, &KEY_128_BIT[..]).expect("valid key");

    // 128 bytes input + 16 bytes tag
    let mut buffer = [0u8; 144];
    b.bytes = 128;

    b.iter(|| {
        aead::seal_in_place(
            &sealing_key,
            &NONCE,
            &b""[..],
            &mut buffer,
            sealing_key.algorithm().tag_len(),
        ).unwrap();
    });
}

#[bench]
fn bench_aes_gcm_128_encrypt_1024_bytes(b: &mut Bencher) {
    let sealing_key =
        aead::SealingKey::new(&aead::AES_128_GCM, &KEY_128_BIT[..]).expect("valid key");

    // 1024 bytes input + 16 bytes tag
    let mut buffer = [0u8; 1040];
    b.bytes = 1024;

    b.iter(|| {
        aead::seal_in_place(
            &sealing_key,
            &NONCE,
            &b""[..],
            &mut buffer,
            sealing_key.algorithm().tag_len(),
        ).unwrap();
    });
}

#[bench]
fn bench_aes_gcm_128_encrypt_16384_bytes(b: &mut Bencher) {
    let sealing_key =
        aead::SealingKey::new(&aead::AES_128_GCM, &KEY_128_BIT[..]).expect("valid key");

    // 16384 bytes input + 16 bytes tag
    let mut buffer = [0u8; 16400];
    b.bytes = 16384;

    b.iter(|| {
        aead::seal_in_place(
            &sealing_key,
            &NONCE,
            &b""[..],
            &mut buffer,
            sealing_key.algorithm().tag_len(),
        ).unwrap();
    });
}
