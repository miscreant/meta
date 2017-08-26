// Written in 2015 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

package miscreant

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

type aesSIVExample struct {
	name       string
	key        []byte
	ad         [][]byte
	plaintext  []byte
	ciphertext []byte
}

// Load AES-CMAC test vectors from aes_cmac.tjson
// TODO: switch to a native Go TJSON parser when available
func loadAESSIVExamples(filename string) []aesSIVExample {
	var examplesJSON map[string]interface{}

	exampleData, err := ioutil.ReadFile("../vectors/" + filename)
	if err != nil {
		panic(err)
	}

	if err = json.Unmarshal(exampleData, &examplesJSON); err != nil {
		panic(err)
	}

	examplesArray := examplesJSON["examples:A<O>"].([]interface{})

	if examplesArray == nil {
		panic("no toplevel 'examples:A<O>' key in " + filename)
	}

	result := make([]aesSIVExample, len(examplesArray))

	for i, exampleJSON := range examplesArray {
		example := exampleJSON.(map[string]interface{})

		name := example["name:s"].(string)

		keyHex := example["key:d16"].(string)
		key := make([]byte, hex.DecodedLen(len(keyHex)))

		if _, err := hex.Decode(key, []byte(keyHex)); err != nil {
			panic(err)
		}

		adHeaders := example["ad:A<d16>"].([]interface{})
		ad := make([][]byte, len(adHeaders))

		for j, adHeader := range adHeaders {
			adHeaderHex := adHeader.(string)
			adDecoded := make([]byte, hex.DecodedLen(len(adHeaderHex)))

			if _, err := hex.Decode(adDecoded, []byte(adHeaderHex)); err != nil {
				panic(err)
			}

			ad[j] = adDecoded
		}

		plaintextHex := example["plaintext:d16"].(string)
		plaintext := make([]byte, hex.DecodedLen(len(plaintextHex)))

		if _, err := hex.Decode(plaintext, []byte(plaintextHex)); err != nil {
			panic(err)
		}

		ciphertextHex := example["ciphertext:d16"].(string)
		ciphertext := make([]byte, hex.DecodedLen(len(ciphertextHex)))

		if _, err := hex.Decode(ciphertext, []byte(ciphertextHex)); err != nil {
			panic(err)
		}

		result[i] = aesSIVExample{name, key, ad, plaintext, ciphertext}
	}

	return result
}

func TestAESCMACSIV(t *testing.T) {
	for i, v := range loadAESSIVExamples("aes_siv.tjson") {
		c, err := NewAESCMACSIV(v.key)
		if err != nil {
			t.Errorf("NewAESCMACSIV: %d: %s", i, err)
		}

		ct, err := c.Seal(nil, v.plaintext, v.ad...)
		if err != nil {
			t.Errorf("Seal: %d: %s", i, err)
		}
		if !bytes.Equal(v.ciphertext, ct) {
			t.Errorf("Seal: %d: expected: %x\ngot: %x", i, v.ciphertext, ct)
		}
		pt, err := c.Open(nil, ct, v.ad...)
		if err != nil {
			t.Errorf("Open: %d: %s", i, err)
		}
		if !bytes.Equal(v.plaintext, pt) {
			t.Errorf("Open: %d: expected: %x\ngot: %x", i, v.plaintext, pt)
		}
	}
}

func TestAESPMACSIV(t *testing.T) {
	for i, v := range loadAESSIVExamples("aes_pmac_siv.tjson") {
		c, err := NewAESPMACSIV(v.key)
		if err != nil {
			t.Errorf("NewAESPMACSIV: %d: %s", i, err)
		}

		ct, err := c.Seal(nil, v.plaintext, v.ad...)
		if err != nil {
			t.Errorf("Seal: %d: %s", i, err)
		}
		if !bytes.Equal(v.ciphertext, ct) {
			t.Errorf("Seal: %d: expected: %x\ngot: %x", i, v.ciphertext, ct)
		}
		pt, err := c.Open(nil, ct, v.ad...)
		if err != nil {
			t.Errorf("Open: %d: %s", i, err)
		}
		if !bytes.Equal(v.plaintext, pt) {
			t.Errorf("Open: %d: expected: %x\ngot: %x", i, v.plaintext, pt)
		}
	}
}

func TestAESCMACSIVAppend(t *testing.T) {
	v := loadAESSIVExamples("aes_siv.tjson")[0]

	c, err := NewAESCMACSIV(v.key)
	if err != nil {
		t.Fatalf("NewAESCMACSIV: %s", err)
	}
	out := []byte{1, 2, 3, 4}
	x, err := c.Seal(out, v.plaintext, v.ad...)
	if err != nil {
		t.Fatalf("Seal: %s", err)
	}
	if !bytes.Equal(x[:4], out[:4]) {
		t.Fatalf("Seal: didn't correctly append")
	}

	out = make([]byte, 4, 100)
	x, err = c.Seal(out, v.plaintext, v.ad...)
	if err != nil {
		t.Fatalf("Seal: %s", err)
	}
	if !bytes.Equal(x[:4], out[:4]) {
		t.Fatalf("Seal: didn't correctly append with sufficient capacity")
	}

	out = make([]byte, 4)
	x, err = c.Open(out, v.ciphertext, v.ad...)
	if err != nil {
		t.Fatalf("Open: %s", err)
	}
	if !bytes.Equal(x[:4], out[:4]) {
		t.Fatalf("Open: didn't correctly append")
	}

	out = make([]byte, 4, 100)
	x, err = c.Open(out, v.ciphertext, v.ad...)
	if err != nil {
		t.Fatalf("Open: %s", err)
	}
	if !bytes.Equal(x[:4], out[:4]) {
		t.Fatalf("Open: didn't correctly append with sufficient capacity")
	}
}

func BenchmarkSIVAES128_Seal_1K(b *testing.B) {
	a := make([]byte, 64)
	m := make([]byte, 1024)
	c, _ := NewAESCMACSIV(make([]byte, 32))
	out := make([]byte, 0, len(m)+c.Overhead())
	b.SetBytes(int64(len(m)))
	for i := 0; i < b.N; i++ {
		_, _ = c.Seal(out, m, a)
	}
}

func BenchmarkSIVAES128_Seal_8K(b *testing.B) {
	a := make([]byte, 64)
	m := make([]byte, 8192)
	c, _ := NewAESCMACSIV(make([]byte, 32))
	b.SetBytes(int64(len(m)))
	out := make([]byte, 0, len(m)+c.Overhead())
	for i := 0; i < b.N; i++ {
		_, _ = c.Seal(out, m, a)
	}
}

func BenchmarkSIVAES128_Open_1K(b *testing.B) {
	a := make([]byte, 64)
	m := make([]byte, 1024)
	c, _ := NewAESCMACSIV(make([]byte, 32))
	x, _ := c.Seal(nil, m, a)
	out := make([]byte, 0, len(m))
	b.SetBytes(int64(len(m)))
	for i := 0; i < b.N; i++ {
		_, _ = c.Open(out, x, a)
	}
}

func BenchmarkSIVAES128_Open_8K(b *testing.B) {
	a := make([]byte, 64)
	m := make([]byte, 8192)
	c, _ := NewAESCMACSIV(make([]byte, 32))
	x, _ := c.Seal(nil, m, a)
	out := make([]byte, 0, len(m))
	b.SetBytes(int64(len(m)))
	for i := 0; i < b.N; i++ {
		_, _ = c.Open(out, x, a)
	}
}
