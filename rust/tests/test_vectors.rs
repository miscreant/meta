extern crate data_encoding;
extern crate serde_json;

use self::data_encoding::HEXLOWER;
pub use self::serde_json::Value as JsonValue;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// AES block cipher test vectors
// TODO: switch to the tjson crate (based on serde)
#[derive(Debug)]
pub struct AesExample {
    pub key: Vec<u8>,
    pub src: Vec<u8>,
    pub dst: Vec<u8>,
}

impl AesExample {
    /// Load examples from aes.tjson
    pub fn load_all() -> Vec<Self> {
        Self::load_from_file(Path::new("../vectors/aes.tjson"))
    }

    /// Load examples from a file at the given path
    pub fn load_from_file(path: &Path) -> Vec<Self> {
        let mut file = File::open(&path).expect("valid aes.tjson");
        let mut tjson_string = String::new();
        file.read_to_string(&mut tjson_string).expect(
            "aes.tjson read successfully",
        );

        let tjson: serde_json::Value =
            serde_json::from_str(&tjson_string).expect("aes.tjson parses successfully");
        let examples = &tjson["examples:A<O>"].as_array().expect(
            "aes.tjson examples array",
        );

        examples
            .into_iter()
            .map(|ex| {
                Self {
                    key: HEXLOWER
                        .decode(ex["key:d16"].as_str().expect("encoded example").as_bytes())
                        .expect("hex encoded"),
                    src: HEXLOWER
                        .decode(ex["src:d16"].as_str().expect("encoded example").as_bytes())
                        .expect("hex encoded"),
                    dst: HEXLOWER
                        .decode(ex["dst:d16"].as_str().expect("encoded example").as_bytes())
                        .expect("hex encoded"),
                }
            })
            .collect()
    }
}

/// AES-CMAC test vectors
// TODO: switch to the tjson crate (based on serde)
#[derive(Debug)]
pub struct AesCmacExample {
    pub key: Vec<u8>,
    pub message: Vec<u8>,
    pub tag: Vec<u8>,
}

impl AesCmacExample {
    /// Load examples from aes_cmac.tjson
    pub fn load_all() -> Vec<Self> {
        Self::load_from_file(Path::new("../vectors/aes_cmac.tjson"))
    }

    /// Load examples from a file at the given path
    pub fn load_from_file(path: &Path) -> Vec<Self> {
        let mut file = File::open(&path).expect("valid aes_cmac.tjson");
        let mut tjson_string = String::new();
        file.read_to_string(&mut tjson_string).expect(
            "aes_cmac.tjson read successfully",
        );

        let tjson: serde_json::Value =
            serde_json::from_str(&tjson_string).expect("aes_cmac.tjson parses successfully");
        let examples = &tjson["examples:A<O>"].as_array().expect(
            "aes_cmac.tjson examples array",
        );

        examples
            .into_iter()
            .map(|ex| {
                Self {
                    key: HEXLOWER
                        .decode(ex["key:d16"].as_str().expect("encoded example").as_bytes())
                        .expect("hex encoded"),
                    message: HEXLOWER
                        .decode(
                            ex["message:d16"]
                                .as_str()
                                .expect("encoded example")
                                .as_bytes(),
                        )
                        .expect("hex encoded"),
                    tag: HEXLOWER
                        .decode(ex["tag:d16"].as_str().expect("encoded example").as_bytes())
                        .expect("hex encoded"),
                }
            })
            .collect()
    }
}

/// AES-CTR test vectors
// TODO: switch to the tjson crate (based on serde)
#[derive(Debug)]
pub struct AesCtrExample {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl AesCtrExample {
    /// Load examples from aes_ctr.tjson
    pub fn load_all() -> Vec<Self> {
        Self::load_from_file(Path::new("../vectors/aes_ctr.tjson"))
    }

    /// Load examples from a file at the given path
    pub fn load_from_file(path: &Path) -> Vec<Self> {
        let mut file = File::open(&path).expect("valid aes_ctr.tjson");
        let mut tjson_string = String::new();
        file.read_to_string(&mut tjson_string).expect(
            "aes_ctr.tjson read successfully",
        );

        let tjson: serde_json::Value =
            serde_json::from_str(&tjson_string).expect("aes_ctr.tjson parses successfully");
        let examples = &tjson["examples:A<O>"].as_array().expect(
            "aes_ctr.tjson examples array",
        );

        examples
            .into_iter()
            .map(|ex| {
                Self {
                    key: HEXLOWER
                        .decode(ex["key:d16"].as_str().expect("encoded example").as_bytes())
                        .expect("hex encoded"),
                    iv: HEXLOWER
                        .decode(ex["iv:d16"].as_str().expect("encoded example").as_bytes())
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

/// AES-PMAC test vectors
// TODO: switch to the tjson crate (based on serde)
#[derive(Debug)]
pub struct AesPmacExample {
    pub key: Vec<u8>,
    pub message: Vec<u8>,
    pub tag: Vec<u8>,
}

impl AesPmacExample {
    /// Load examples from aes_pmac.tjson
    pub fn load_all() -> Vec<Self> {
        Self::load_from_file(Path::new("../vectors/aes_pmac.tjson"))
    }

    /// Load examples from a file at the given path
    pub fn load_from_file(path: &Path) -> Vec<Self> {
        let mut file = File::open(&path).expect("valid aes_pmac.tjson");
        let mut tjson_string = String::new();
        file.read_to_string(&mut tjson_string).expect(
            "aes_pmac.tjson read successfully",
        );

        let tjson: serde_json::Value =
            serde_json::from_str(&tjson_string).expect("aes_pmac.tjson parses successfully");
        let examples = &tjson["examples:A<O>"].as_array().expect(
            "aes_pmac.tjson examples array",
        );

        examples
            .into_iter()
            .map(|ex| {
                Self {
                    key: HEXLOWER
                        .decode(ex["key:d16"].as_str().expect("encoded example").as_bytes())
                        .expect("hex encoded"),
                    message: HEXLOWER
                        .decode(
                            ex["message:d16"]
                                .as_str()
                                .expect("encoded example")
                                .as_bytes(),
                        )
                        .expect("hex encoded"),
                    tag: HEXLOWER
                        .decode(ex["tag:d16"].as_str().expect("encoded example").as_bytes())
                        .expect("hex encoded"),
                }
            })
            .collect()
    }
}

/// AES-SIV test vectors
// TODO: switch to the tjson crate (based on serde)
#[derive(Debug)]
pub struct AesSivExample {
    pub key: Vec<u8>,
    pub ad: Vec<Vec<u8>>,
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl AesSivExample {
    /// Load examples from aes_siv.tjson
    pub fn load_all() -> Vec<Self> {
        Self::load_from_file(Path::new("../vectors/aes_siv.tjson"))
    }

    /// Load examples from a file at the given path
    pub fn load_from_file(path: &Path) -> Vec<Self> {
        let mut file = File::open(&path).expect("valid aes_siv.tjson");
        let mut tjson_string = String::new();
        file.read_to_string(&mut tjson_string).expect(
            "aes_siv.tjson read successfully",
        );

        let tjson: serde_json::Value =
            serde_json::from_str(&tjson_string).expect("aes_siv.tjson parses successfully");
        let examples = &tjson["examples:A<O>"].as_array().expect(
            "aes_siv.tjson examples array",
        );

        examples
            .into_iter()
            .map(|ex| {
                Self {
                    key: HEXLOWER
                        .decode(ex["key:d16"].as_str().expect("encoded example").as_bytes())
                        .expect("hex encoded"),
                    ad: ex["ad:A<d16>"]
                        .as_array()
                        .expect("encoded example")
                        .iter()
                        .map(|ex| {
                            HEXLOWER
                                .decode(ex.as_str().expect("encoded example").as_bytes())
                                .expect("hex encoded")
                        })
                        .collect(),
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

/// AES-SIV test vectors
// TODO: switch to the tjson crate (based on serde)
#[derive(Debug)]
pub struct AesPmacSivExample {
    pub key: Vec<u8>,
    pub ad: Vec<Vec<u8>>,
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl AesPmacSivExample {
    /// Load examples from aes_pmac_siv.tjson
    pub fn load_all() -> Vec<Self> {
        Self::load_from_file(Path::new("../vectors/aes_pmac_siv.tjson"))
    }

    /// Load examples from a file at the given path
    pub fn load_from_file(path: &Path) -> Vec<Self> {
        let mut file = File::open(&path).expect("valid aes_pmac_siv.tjson");
        let mut tjson_string = String::new();
        file.read_to_string(&mut tjson_string).expect(
            "aes_pmac_siv.tjson read successfully",
        );

        let tjson: serde_json::Value =
            serde_json::from_str(&tjson_string).expect("aes_pmac_siv.tjson parses successfully");
        let examples = &tjson["examples:A<O>"].as_array().expect(
            "aes_pmac_siv.tjson examples array",
        );

        examples
            .into_iter()
            .map(|ex| {
                Self {
                    key: HEXLOWER
                        .decode(ex["key:d16"].as_str().expect("encoded example").as_bytes())
                        .expect("hex encoded"),
                    ad: ex["ad:A<d16>"]
                        .as_array()
                        .expect("encoded example")
                        .iter()
                        .map(|ex| {
                            HEXLOWER
                                .decode(ex.as_str().expect("encoded example").as_bytes())
                                .expect("hex encoded")
                        })
                        .collect(),
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

/// dbl() test vectors
// TODO: switch to the tjson crate (based on serde)
#[derive(Debug)]
pub struct DblExample {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
}

impl DblExample {
    /// Load examples from dbl.tjson
    pub fn load_all() -> Vec<Self> {
        Self::load_from_file(Path::new("../vectors/dbl.tjson"))
    }

    /// Load examples from a file at the given path
    pub fn load_from_file(path: &Path) -> Vec<Self> {
        let mut file = File::open(&path).expect("valid dbl.tjson");
        let mut tjson_string = String::new();
        file.read_to_string(&mut tjson_string).expect(
            "dbl.tjson read successfully",
        );

        let tjson: serde_json::Value =
            serde_json::from_str(&tjson_string).expect("dbl.tjson parses successfully");
        let examples = &tjson["examples:A<O>"].as_array().expect(
            "dbl.tjson examples array",
        );

        examples
            .into_iter()
            .map(|ex| {
                Self {
                    input: HEXLOWER
                        .decode(
                            ex["input:d16"]
                                .as_str()
                                .expect("encoded example")
                                .as_bytes(),
                        )
                        .expect("hex encoded"),
                    output: HEXLOWER
                        .decode(
                            ex["output:d16"]
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
