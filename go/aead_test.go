// Written in 2015 by Dmitry Chestnykh.

package miscreant

import (
	"bytes"
	"testing"
)

func TestAEADAESCMACSIV(t *testing.T) {
	v := loadAESSIVExamples("aes_siv.tjson")[0]
	nonce := v.ad[0]
	c, err := NewAEAD("AES-SIV", v.key, len(nonce))
	if err != nil {
		t.Fatal(err)
	}
	ct := c.Seal(nil, nonce, v.plaintext, nil)
	if !bytes.Equal(v.ciphertext, ct) {
		t.Errorf("Seal: expected: %x\ngot: %x", v.ciphertext, ct)
	}
	pt, err := c.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Errorf("Open: %s", err)
	}
	if !bytes.Equal(v.plaintext, pt) {
		t.Errorf("Open: expected: %x\ngot: %x", v.plaintext, pt)
	}
}

func TestAEADAESPMACSIV(t *testing.T) {
	v := loadAESSIVExamples("aes_pmac_siv.tjson")[0]
	nonce := v.ad[0]
	c, err := NewAEAD("AES-PMAC-SIV", v.key, len(nonce))
	if err != nil {
		t.Fatal(err)
	}
	ct := c.Seal(nil, nonce, v.plaintext, nil)
	if !bytes.Equal(v.ciphertext, ct) {
		t.Errorf("Seal: expected: %x\ngot: %x", v.ciphertext, ct)
	}
	pt, err := c.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Errorf("Open: %s", err)
	}
	if !bytes.Equal(v.plaintext, pt) {
		t.Errorf("Open: expected: %x\ngot: %x", v.plaintext, pt)
	}
}
