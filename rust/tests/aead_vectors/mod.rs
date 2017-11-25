extern crate data_encoding;
extern crate serde_json;

use self::data_encoding::HEXLOWER;
pub use self::serde_json::Value as JsonValue;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// AES-SIV test vectors for AEAD API (CMAC and PMAC)
// TODO: switch to the tjson crate (based on serde)
#[derive(Debug)]
pub struct AesSivAeadExample {
    pub alg: String,
    pub key: Vec<u8>,
    pub ad: Vec<u8>,
    pub nonce: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl AesSivAeadExample {
    /// Load examples from aes_siv_aead.tjson
    pub fn load_all() -> Vec<Self> {
        Self::load_from_file(Path::new("../vectors/aes_siv_aead.tjson"))
    }

    /// Load examples from a file at the given path
    pub fn load_from_file(path: &Path) -> Vec<Self> {
        let mut file = File::open(&path).expect("valid aes_siv_aead.tjson");
        let mut tjson_string = String::new();

        file.read_to_string(&mut tjson_string).expect(
            "aes_siv_aead.tjson read successfully",
        );

        let tjson: serde_json::Value =
            serde_json::from_str(&tjson_string).expect("aes_siv.tjson parses successfully");

        let examples = &tjson["examples:A<O>"].as_array().expect(
            "aes_siv_aead.tjson examples array",
        );

        examples
            .into_iter()
            .map(|ex| {
                Self {
                    alg: ex["alg:s"].as_str().expect("algorithm name").to_owned(),
                    key: HEXLOWER
                        .decode(ex["key:d16"].as_str().expect("encoded example").as_bytes())
                        .expect("hex encoded"),
                    ad: HEXLOWER
                        .decode(ex["ad:d16"].as_str().expect("encoded example").as_bytes())
                        .expect("hex encoded"),
                    nonce: HEXLOWER
                        .decode(
                            ex["nonce:d16"]
                                .as_str()
                                .expect("encoded example")
                                .as_bytes(),
                        )
                        .expect("hex encoded"),
                    plaintext: HEXLOWER
                        .decode(
                            ex["plaintext:d16"]
                                .as_str()
                                .expect("encoded example")
                                .as_bytes(),
                        )
                        .expect("hex encoded"),
                    ciphertext: HEXLOWER
                        .decode(
                            ex["ciphertext:d16"]
                                .as_str()
                                .expect("encoded example")
                                .as_bytes(),
                        )
                        .expect("hex encoded"),
                }
            })
            .collect()
    }
}
