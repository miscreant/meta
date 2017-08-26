// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmac

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

type cmacAESExample struct {
	key     []byte
	message []byte
	tag     []byte
}

// Load AES-CMAC test vectors from aes_cmac.tjson
// TODO: switch to a native Go TJSON parser when available
func loadCMACAESExamples() []cmacAESExample {
	var examplesJSON map[string]interface{}

	exampleData, err := ioutil.ReadFile("../../vectors/aes_cmac.tjson")
	if err != nil {
		panic(err)
	}

	if err = json.Unmarshal(exampleData, &examplesJSON); err != nil {
		panic(err)
	}

	examplesArray := examplesJSON["examples:A<O>"].([]interface{})

	if examplesArray == nil {
		panic("no toplevel 'examples:A<O>' key in aes_cmac.tjson")
	}

	result := make([]cmacAESExample, len(examplesArray))

	for i, exampleJSON := range examplesArray {
		example := exampleJSON.(map[string]interface{})

		keyHex := example["key:d16"].(string)
		key := make([]byte, hex.DecodedLen(len(keyHex)))

		if _, err := hex.Decode(key, []byte(keyHex)); err != nil {
			panic(err)
		}

		messageHex := example["message:d16"].(string)
		message := make([]byte, hex.DecodedLen(len(messageHex)))

		if _, err := hex.Decode(message, []byte(messageHex)); err != nil {
			panic(err)
		}

		tagHex := example["tag:d16"].(string)
		tag := make([]byte, hex.DecodedLen(len(tagHex)))

		if _, err := hex.Decode(tag, []byte(tagHex)); err != nil {
			panic(err)
		}

		result[i] = cmacAESExample{key, message, tag}
	}

	return result
}

func TestCMACAES(t *testing.T) {
	for i, tt := range loadCMACAESExamples() {
		c, err := aes.NewCipher(tt.key)
		if err != nil {
			t.Errorf("test %d: NewCipher: %s", i, err)
			continue
		}
		d := New(c)
		n, err := d.Write(tt.message)
		if err != nil || n != len(tt.message) {
			t.Errorf("test %d: Write %d: %d, %s", i, len(tt.message), n, err)
			continue
		}
		sum := d.Sum(nil)
		if !bytes.Equal(sum, tt.tag) {
			x := d.(*cmac)
			t.Errorf("test %d: tag mismatch\n\twant %x\n\thave %x\n\tk1 %x\n\tk2 %x", i, tt.tag, sum, x.k1, x.k2)
			continue
		}
	}
}

func TestWrite(t *testing.T) {
	cmacAESTests := loadCMACAESExamples()
	tt := cmacAESTests[len(cmacAESTests)-1]
	c, err := aes.NewCipher(tt.key)
	if err != nil {
		t.Fatal(err)
	}
	d := New(c)

	// Test writing byte-by-byte
	for _, b := range tt.message {
		_, err := d.Write([]byte{b})
		if err != nil {
			t.Fatal(err)
		}
	}
	sum := d.Sum(nil)
	if !bytes.Equal(sum, tt.tag) {
		x := d.(*cmac)
		t.Fatalf("write bytes: tag mismatch\n\twant %x\n\thave %x\n\tk1 %x\n\tk2 %x", tt.tag, sum, x.k1, x.k2)
	}

	// Test writing halves
	d.Reset()

	_, err = d.Write(tt.message[:len(tt.message)/2])
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Write(tt.message[len(tt.message)/2:])
	if err != nil {
		t.Fatal(err)
	}

	sum = d.Sum(nil)
	if !bytes.Equal(sum, tt.tag) {
		x := d.(*cmac)
		t.Fatalf("write halves: tag mismatch\n\twant %x\n\thave %x\n\tk1 %x\n\tk2 %x", tt.tag, sum, x.k1, x.k2)
	}

	// Test writing third, then the rest
	d.Reset()
	_, err = d.Write(tt.message[:len(tt.message)/3])
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Write(tt.message[len(tt.message)/3:])
	if err != nil {
		t.Fatal(err)
	}

	sum = d.Sum(nil)
	if !bytes.Equal(sum, tt.tag) {
		x := d.(*cmac)
		t.Fatalf("write third: tag mismatch\n\twant %x\n\thave %x\n\tk1 %x\n\tk2 %x", tt.tag, sum, x.k1, x.k2)
	}

	// Test continuing after Sum
	d.Reset()

	_, err = d.Write(tt.message[:len(tt.message)/2])
	if err != nil {
		t.Fatal(err)
	}

	sum = d.Sum(nil)

	_, err = d.Write(tt.message[len(tt.message)/2:])
	if err != nil {
		t.Fatal(err)
	}

	sum = d.Sum(nil)
	if !bytes.Equal(sum, tt.tag) {
		x := d.(*cmac)
		t.Fatalf("continue after Sum: tag mismatch\n\twant %x\n\thave %x\n\tk1 %x\n\tk2 %x", tt.tag, sum, x.k1, x.k2)
	}
}

func BenchmarkCMAC_AES128(b *testing.B) {
	cmacAESTests := loadCMACAESExamples()
	c, _ := aes.NewCipher(cmacAESTests[0].key)
	v := make([]byte, 1024)
	out := make([]byte, 16)
	b.SetBytes(int64(len(v)))
	for i := 0; i < b.N; i++ {
		d := New(c)
		_, err := d.Write(v)
		if err != nil {
			panic(err)
		}
		out = d.Sum(out[:0])
	}
}
