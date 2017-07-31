#[macro_use]
extern crate arrayref;
extern crate miscreant;

use miscreant::{Aes128Siv, Aes256Siv};
use miscreant::internals::{Aes128, Aes256, Block, BlockCipher, Cmac, Ctr};
use miscreant::internals::BLOCK_SIZE;

mod test_vectors;
use test_vectors::{AesExample, AesCmacExample, AesCtrExample, AesSivExample, DblExample};

#[test]
fn aes_examples() {
    let examples = AesExample::load_all();

    for example in examples {
        let mut block = Block::new();
        block.as_mut().copy_from_slice(&example.src);

        match example.key.len() {
            16 => {
                let aes = Aes128::new(array_ref!(example.key, 0, 16));
                aes.encrypt(&mut block);
            }
            32 => {
                let aes = Aes256::new(array_ref!(example.key, 0, 32));
                aes.encrypt(&mut block);
            }
            _ => panic!("unexpected key size: {}", example.key.len()),
        }

        assert_eq!(block.as_ref(), array_ref!(example.dst, 0, 16));
    }
}

#[test]
fn aes_cmac_examples() {
    let examples = AesCmacExample::load_all();

    for example in examples {
        let result = match example.key.len() {
            16 => {
                let aes = Aes128::new(array_ref!(example.key, 0, 16));
                let mut aes_cmac = Cmac::new(aes);

                aes_cmac.update(&example.message);
                aes_cmac.finish()
            }
            32 => {
                let aes = Aes256::new(array_ref!(example.key, 0, 32));
                let mut aes_cmac = Cmac::new(aes);

                aes_cmac.update(&example.message);
                aes_cmac.finish()
            }
            _ => panic!("unexpected key size: {}", example.key.len()),
        };

        assert_eq!(result.as_ref(), array_ref!(example.tag, 0, 16));
    }
}

#[test]
fn aes_ctr_examples() {
    let examples = AesCtrExample::load_all();

    for example in examples {
        let mut buffer = example.plaintext.clone();

        match example.key.len() {
            16 => {
                let aes = Aes128::new(array_ref!(example.key, 0, 16));
                let mut aes_ctr = Ctr::new(aes);
                let mut iv = Block::from(&example.iv[..]);
                aes_ctr.transform(&mut iv, &mut buffer);
            }
            32 => {
                let aes = Aes256::new(array_ref!(example.key, 0, 32));
                let mut aes_ctr = Ctr::new(aes);
                let mut iv = Block::from(&example.iv[..]);
                aes_ctr.transform(&mut iv, &mut buffer);
            }
            _ => panic!("unexpected key size: {}", example.key.len()),
        };

        assert_eq!(buffer, example.ciphertext);
    }
}

#[test]
fn aes_siv_examples_seal() {
    let examples = AesSivExample::load_all();

    for example in examples {
        let len = example.plaintext.len();
        let mut buffer = vec![0; len + BLOCK_SIZE];
        buffer[..len].copy_from_slice(&example.plaintext);

        match example.key.len() {
            32 => {
                let mut siv = Aes128Siv::new(array_ref!(example.key, 0, 32));
                siv.seal_in_place(&example.ad, &mut buffer);
            }
            64 => {
                let mut siv = Aes256Siv::new(array_ref!(example.key, 0, 64));
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
                let mut siv = Aes128Siv::new(array_ref!(example.key, 0, 32));
                siv.open_in_place(&example.ad, &mut buffer)
            }
            64 => {
                let mut siv = Aes256Siv::new(array_ref!(example.key, 0, 64));
                siv.open_in_place(&example.ad, &mut buffer)
            }
            _ => panic!("unexpected key size: {}", example.key.len()),
        }.expect("successful decrypt");

        assert_eq!(plaintext, &example.plaintext[..]);
    }
}

#[test]
fn dbl_examples() {
    let examples = DblExample::load_all();
    for example in examples {
        let mut block = Block::from(&example.input[..]);
        block.dbl();
        assert_eq!(block.as_ref(), &example.output[..]);
    }
}
