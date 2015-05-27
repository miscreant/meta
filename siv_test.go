// Written in 2015 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

package siv

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

var testVectors = []struct {
	key       string
	adata     []string
	plaintext string
	output    string
}{
	// A.1.  Deterministic Authenticated Encryption Example
	{
		"fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff",
		[]string{"10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627"},
		"11223344 55667788 99aabbcc ddee",
		"85632d07 c6e8f37f 950acd32 0a2ecc93 40c02b96 90c4dc04 daef7f6a fe5c",
	},
	//A.2.  Nonce-Based Authenticated Encryption Example
	{
		"7f7e7d7c 7b7a7978 77767574 73727170 40414243 44454647 48494a4b 4c4d4e4f",
		[]string{
			"00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100", //AD1
			"10203040 50607080 90a0",                                                                    //AD2
			"09f91102 9d74e35b d84156c5 635688c0",                                                       // nonce
		},
		"74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720 5349562d 414553",
		"7bdb6e3b 432667eb 06f4d14b ff2fbd0f cb900f2f ddbe4043 26601965 c889bf17 dba77ceb 094fa663 b7a3f748 ba8af829 ea64ad54 4a272e9c 485b62a3 fd5c0d",
	},
	{
		"fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff",
		[]string{},
		"",
		"f2007a5beb2b8900c588a7adf599f172", //TODO(dchest): verify this with other implementations
	},
	// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/siv/siv-test-vectors.txt
	// TEST CASE #1
	// 192 bit subkeys
	{
		"fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 6f6e6d6c 6b6a6968 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff 00010203 04050607",
		[]string{"10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627"},
		"11223344 55667788 99aabbcc ddee",
		"02347811 daa8b274 91f24448 932775a6 2af34a06 ac0016e8 ac284a55 14f6",
	},
	// 256 bit subkeys
	{
		"fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 6f6e6d6c 6b6a6968 67666564 63626160 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff 00010203 04050607 08090a0b 0c0d0e0f",
		[]string{"10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627"},
		"11223344 55667788 99aabbcc ddee",
		"f125274c 598065cf c26b0e71 57502908 8b035217 e380cac8 919ee800 c126",
	},
	// TEST CASE #2
	// 192 bit subkeys
	{
		"7f7e7d7c 7b7a7978 77767574 73727170 6f6e6d6c 6b6a6968 40414243 44454647 48494a4b 4c4d4e4f 50515253 54555657",
		[]string{
			"00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100",
			"10203040 50607080 90a0",
			"09f91102 9d74e35b d84156c5 635688c0",
		},
		"74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720 5349562d 414553",
		"de40aa1e 7180d519 cb14308e a7f77586 da09877c 510f2965 1f42311a b728e956 09e7de29 94bdf80b b99bfaac e31c4ec0 d15ba650 9f53f36a d725dcab c9e2a7",
	},
	// 256 bit subkeys
	{
		"7f7e7d7c 7b7a7978 77767574 73727170 6f6e6d6c 6b6a6968 67666564 63626160 40414243 44454647 48494a4b 4c4d4e4f 50515253 54555657 58595a5b 5b5d5e5f",
		[]string{
			"00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100",
			"10203040 50607080 90a0",
			"09f91102 9d74e35b d84156c5 635688c0",
		},
		"74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720 5349562d 414553",
		"85b81673 10038db7 dc4692c0 281ca358 68181b27 62f3c24f 2efa5fb8 0cb14351 6ce6c434 b898a6fd 8eb98a41 8842f51f 66fc67de 43ac185a 66dd7247 5bbb08",
	},
	//TODO(dchest): find more test vectors.
}

func decode(s string) []byte {
	b, err := hex.DecodeString(strings.Replace(s, " ", "", -1))
	if err != nil {
		panic(err.Error())
	}
	return b
}

func decodeAD(ad []string) [][]byte {
	b := make([][]byte, len(ad))
	for i, s := range ad {
		b[i] = decode(s)
	}
	return b
}

func TestAES(t *testing.T) {
	for i, v := range testVectors {
		c, err := NewAES(decode(v.key))
		if err != nil {
			t.Errorf("NewAES: %d: %s", i, err)
		}
		gpt, gct, ad := decode(v.plaintext), decode(v.output), decodeAD(v.adata)
		ct, err := c.Seal(nil, gpt, ad...)
		if err != nil {
			t.Errorf("Seal: %d: %s", i, err)
		}
		if !bytes.Equal(gct, ct) {
			t.Errorf("Seal: %d: expected: %x\ngot: %x", i, gct, ct)
		}
		pt, err := c.Open(nil, ct, ad...)
		if err != nil {
			t.Errorf("Open: %d: %s", i, err)
		}
		if !bytes.Equal(gpt, pt) {
			t.Errorf("Open: %d: expected: %x\ngot: %x", i, gpt, pt)
		}
	}
}

func TestAppend(t *testing.T) {
	v := testVectors[0]
	m := decode(v.plaintext)
	o := decode(v.output)
	a := decodeAD(v.adata)
	c, err := NewAES(decode(v.key))
	if err != nil {
		t.Fatalf("NewAES: %s", err)
	}
	out := []byte{1, 2, 3, 4}
	x, err := c.Seal(out, m, a...)
	if err != nil {
		t.Fatalf("Seal: %s", err)
	}
	if !bytes.Equal(x[:4], out[:4]) {
		t.Fatalf("Seal: didn't correctly append")
	}

	out = make([]byte, 4, 100)
	x, err = c.Seal(out, m, a...)
	if err != nil {
		t.Fatalf("Seal: %s", err)
	}
	if !bytes.Equal(x[:4], out[:4]) {
		t.Fatalf("Seal: didn't correctly append with sufficient capacity")
	}

	out = make([]byte, 4)
	x, err = c.Open(out, o, a...)
	if err != nil {
		t.Fatalf("Open: %s", err)
	}
	if !bytes.Equal(x[:4], out[:4]) {
		t.Fatalf("Open: didn't correctly append")
	}

	out = make([]byte, 4, 100)
	x, err = c.Open(out, o, a...)
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
	c, _ := NewAES(make([]byte, 32))
	out := make([]byte, 0, len(m)+c.Overhead())
	b.SetBytes(int64(len(m)))
	for i := 0; i < b.N; i++ {
		c.Seal(out, m, a)
	}
}

func BenchmarkSIVAES128_Seal_8K(b *testing.B) {
	a := make([]byte, 64)
	m := make([]byte, 8192)
	c, _ := NewAES(make([]byte, 32))
	b.SetBytes(int64(len(m)))
	out := make([]byte, 0, len(m)+c.Overhead())
	for i := 0; i < b.N; i++ {
		c.Seal(out, m, a)
	}
}

func BenchmarkSIVAES128_Open_1K(b *testing.B) {
	a := make([]byte, 64)
	m := make([]byte, 1024)
	c, _ := NewAES(make([]byte, 32))
	x, _ := c.Seal(nil, m, a)
	out := make([]byte, 0, len(m))
	b.SetBytes(int64(len(m)))
	for i := 0; i < b.N; i++ {
		c.Open(out, x, a)
	}
}

func BenchmarkSIVAES128_Open_8K(b *testing.B) {
	a := make([]byte, 64)
	m := make([]byte, 8192)
	c, _ := NewAES(make([]byte, 32))
	x, _ := c.Seal(nil, m, a)
	out := make([]byte, 0, len(m))
	b.SetBytes(int64(len(m)))
	for i := 0; i < b.N; i++ {
		c.Open(out, x, a)
	}
}
