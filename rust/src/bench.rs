extern crate ring;

use self::ring::aead;
use {Aes128Siv, Aes128PmacSiv};
use internals::{Aes128Cmac, Aes128Ctr, Aes128Pmac, Block, Ctr, Mac};
use test::Bencher;

// WARNING: Do not ever actually use a key of all zeroes
const KEY_128_BIT: [u8; 16] = [0u8; 16];
const KEY_256_BIT: [u8; 32] = [0u8; 32];

const NONCE: [u8; 12] = [0u8; 12];

//
// AES-CMAC benchmarks
//

#[bench]
fn bench_aes_cmac_128_mac_128_bytes(b: &mut Bencher) {
    let mut cmac = Aes128Cmac::new(&KEY_128_BIT);

    // 128 bytes input + 16 bytes tag
    let buffer = [0u8; 144];
    b.bytes = 128;

    b.iter(|| {
        cmac.update(&buffer);
        cmac.finish();
        cmac.reset();
    });
}

#[bench]
fn bench_aes_cmac_128_mac_1024_bytes(b: &mut Bencher) {
    let mut cmac = Aes128Cmac::new(&KEY_128_BIT);

    // 1024 bytes input + 16 bytes tag
    let buffer = [0u8; 1040];
    b.bytes = 1024;

    b.iter(|| {
        cmac.update(&buffer);
        cmac.finish();
        cmac.reset();
    });
}

#[bench]
fn bench_aes_cmac_128_mac_16384_bytes(b: &mut Bencher) {
    let mut cmac = Aes128Cmac::new(&KEY_128_BIT);

    // 16384 bytes input + 16 bytes tag
    let buffer = [0u8; 16400];
    b.bytes = 16384;

    b.iter(|| {
        cmac.update(&buffer);
        cmac.finish();
        cmac.reset();
    });
}

//
// AES-CTR benchmarks
//

#[bench]
fn bench_aes_ctr_128_encrypt_128_bytes(b: &mut Bencher) {
    let ctr = Aes128Ctr::new(&KEY_128_BIT);
    let iv = Block::new();

    // 128 bytes input + 16 bytes tag
    let mut buffer = [0u8; 144];
    b.bytes = 128;
    b.iter(|| ctr.xor_in_place(&iv, &mut buffer));
}

#[bench]
fn bench_aes_ctr_128_encrypt_1024_bytes(b: &mut Bencher) {
    let ctr = Aes128Ctr::new(&KEY_128_BIT);
    let iv = Block::new();

    // 1024 bytes input + 16 bytes tag
    let mut buffer = [0u8; 1040];
    b.bytes = 1024;
    b.iter(|| ctr.xor_in_place(&iv, &mut buffer));
}

#[bench]
fn bench_aes_ctr_128_encrypt_16384_bytes(b: &mut Bencher) {
    let ctr = Aes128Ctr::new(&KEY_128_BIT);
    let iv = Block::new();

    // 16384 bytes input + 16 bytes tag
    let mut buffer = [0u8; 16400];
    b.bytes = 16384;
    b.iter(|| ctr.xor_in_place(&iv, &mut buffer));
}

//
// AES-PMAC benchmarks
//

#[bench]
fn bench_aes_pmac_128_mac_128_bytes(b: &mut Bencher) {
    let mut pmac = Aes128Pmac::new(&KEY_128_BIT);

    // 128 bytes input + 16 bytes tag
    let buffer = [0u8; 144];
    b.bytes = 128;

    b.iter(|| {
        pmac.update(&buffer);
        pmac.finish();
        pmac.reset();
    });
}

#[bench]
fn bench_aes_pmac_128_mac_1024_bytes(b: &mut Bencher) {
    let mut pmac = Aes128Pmac::new(&KEY_128_BIT);

    // 1024 bytes input + 16 bytes tag
    let buffer = [0u8; 1040];
    b.bytes = 1024;

    b.iter(|| {
        pmac.update(&buffer);
        pmac.finish();
        pmac.reset();
    });
}

#[bench]
fn bench_aes_pmac_128_mac_16384_bytes(b: &mut Bencher) {
    let mut pmac = Aes128Pmac::new(&KEY_128_BIT);

    // 16384 bytes input + 16 bytes tag
    let buffer = [0u8; 16400];
    b.bytes = 16384;

    b.iter(|| {
        pmac.update(&buffer);
        pmac.finish();
        pmac.reset();
    });
}

//
// AES-SIV benchmarks
//

#[bench]
fn bench_aes_siv_128_encrypt_128_bytes(b: &mut Bencher) {
    let mut siv = Aes128Siv::new(&KEY_256_BIT);

    // 128 bytes input + 16 bytes tag
    let mut buffer = [0u8; 144];
    b.bytes = 128;

    b.iter(|| { siv.seal_in_place(&[NONCE], &mut buffer); });
}

#[bench]
fn bench_aes_siv_128_encrypt_1024_bytes(b: &mut Bencher) {
    let mut siv = Aes128Siv::new(&KEY_256_BIT);

    // 1024 bytes input + 16 bytes tag
    let mut buffer = [0u8; 1040];
    b.bytes = 1024;

    b.iter(|| { siv.seal_in_place(&[NONCE], &mut buffer); });
}

#[bench]
fn bench_aes_siv_128_encrypt_16384_bytes(b: &mut Bencher) {
    let mut siv = Aes128Siv::new(&KEY_256_BIT);

    // 16384 bytes input + 16 bytes tag
    let mut buffer = [0u8; 16400];
    b.bytes = 16384;

    b.iter(|| { siv.seal_in_place(&[NONCE], &mut buffer); });
}

//
// AES-PMAC-SIV benchmarks
//

#[bench]
fn bench_aes_pmac_siv_128_encrypt_128_bytes(b: &mut Bencher) {
    let mut siv = Aes128PmacSiv::new(&KEY_256_BIT);

    // 128 bytes input + 16 bytes tag
    let mut buffer = [0u8; 144];
    b.bytes = 128;

    b.iter(|| { siv.seal_in_place(&[NONCE], &mut buffer); });
}

#[bench]
fn bench_aes_pmac_siv_128_encrypt_1024_bytes(b: &mut Bencher) {
    let mut siv = Aes128PmacSiv::new(&KEY_256_BIT);

    // 1024 bytes input + 16 bytes tag
    let mut buffer = [0u8; 1040];
    b.bytes = 1024;

    b.iter(|| { siv.seal_in_place(&[NONCE], &mut buffer); });
}

#[bench]
fn bench_aes_pmac_siv_128_encrypt_16384_bytes(b: &mut Bencher) {
    let mut siv = Aes128PmacSiv::new(&KEY_256_BIT);

    // 16384 bytes input + 16 bytes tag
    let mut buffer = [0u8; 16400];
    b.bytes = 16384;

    b.iter(|| { siv.seal_in_place(&[NONCE], &mut buffer); });
}

//
// AES-GCM benchmarks for comparison (using *ring*)
//

#[bench]
fn bench_aes_gcm_128_encrypt_128_bytes(b: &mut Bencher) {
    let sealing_key = aead::SealingKey::new(&aead::AES_128_GCM, &KEY_128_BIT[..])
        .expect("valid key");

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
    let sealing_key = aead::SealingKey::new(&aead::AES_128_GCM, &KEY_128_BIT[..])
        .expect("valid key");

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
    let sealing_key = aead::SealingKey::new(&aead::AES_128_GCM, &KEY_128_BIT[..])
        .expect("valid key");

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
