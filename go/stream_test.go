package miscreant

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

type streamExample struct {
	name   string
	alg    string
	key    []byte
	nonce  []byte
	blocks []streamBlockExample
}

type streamBlockExample struct {
	ad         []byte
	plaintext  []byte
	ciphertext []byte
}

// Load STREAM test vectors from aes_siv_stream.tjson
// TODO: switch to a native Go TJSON parser when available
func loadSTREAMExamples() []streamExample {
	var examplesJSON map[string]interface{}

	exampleData, err := ioutil.ReadFile("../vectors/aes_siv_stream.tjson")
	if err != nil {
		panic(err)
	}

	if err = json.Unmarshal(exampleData, &examplesJSON); err != nil {
		panic(err)
	}

	examplesArray := examplesJSON["examples:A<O>"].([]interface{})

	if examplesArray == nil {
		panic("no toplevel 'examples:A<O>' key in aes_siv_stream.tjson")
	}

	result := make([]streamExample, len(examplesArray))

	for i, exampleJSON := range examplesArray {
		example := exampleJSON.(map[string]interface{})

		name := example["name:s"].(string)
		alg := example["alg:s"].(string)

		keyHex := example["key:d16"].(string)
		key := make([]byte, hex.DecodedLen(len(keyHex)))

		if _, err := hex.Decode(key, []byte(keyHex)); err != nil {
			panic(err)
		}

		nonceHex := example["nonce:d16"].(string)
		nonce := make([]byte, hex.DecodedLen(len(nonceHex)))

		if _, err := hex.Decode(nonce, []byte(nonceHex)); err != nil {
			panic(err)
		}

		blockValues := example["blocks:A<O>"].([]interface{})
		blocks := make([]streamBlockExample, len(blockValues))

		for j, blockJSON := range blockValues {
			block := blockJSON.(map[string]interface{})

			adHex := block["ad:d16"].(string)
			ad := make([]byte, hex.DecodedLen(len(adHex)))

			if _, err := hex.Decode(ad, []byte(adHex)); err != nil {
				panic(err)
			}

			plaintextHex := block["plaintext:d16"].(string)
			plaintext := make([]byte, hex.DecodedLen(len(plaintextHex)))

			if _, err := hex.Decode(plaintext, []byte(plaintextHex)); err != nil {
				panic(err)
			}

			ciphertextHex := block["ciphertext:d16"].(string)
			ciphertext := make([]byte, hex.DecodedLen(len(ciphertextHex)))

			if _, err := hex.Decode(ciphertext, []byte(ciphertextHex)); err != nil {
				panic(err)
			}

			blocks[j] = streamBlockExample{ad, plaintext, ciphertext}
		}

		result[i] = streamExample{name, alg, key, nonce, blocks}
	}

	return result
}

func TestStreamEncryptor(t *testing.T) {
	vectors := loadSTREAMExamples()

	for _, v := range vectors {
		enc, err := NewStreamEncryptor(v.alg, v.key, v.nonce)
		if err != nil {
			t.Fatal(err)
		}

		for i, b := range v.blocks {
			lastBlock := i+1 == len(v.blocks)
			ct := enc.Seal(nil, b.plaintext, b.ad, lastBlock)
			if !bytes.Equal(b.ciphertext, ct) {
				t.Errorf("Seal: expected: %x\ngot: %x", b.ciphertext, ct)
			}
		}
	}
}

func TestStreamDecryptor(t *testing.T) {
	vectors := loadSTREAMExamples()

	for _, v := range vectors {
		dec, err := NewStreamDecryptor(v.alg, v.key, v.nonce)
		if err != nil {
			t.Fatal(err)
		}

		for i, b := range v.blocks {
			lastBlock := i+1 == len(v.blocks)
			pt, err := dec.Open(nil, b.ciphertext, b.ad, lastBlock)

			if err != nil {
				t.Errorf("Open: %s", err)
			}

			if !bytes.Equal(b.plaintext, pt) {
				t.Errorf("Open: expected: %x\ngot: %x", b.plaintext, pt)
			}
		}
	}
}
