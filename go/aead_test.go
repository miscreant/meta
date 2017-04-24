// Written in 2015 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

package sivchain

import (
	"bytes"
	"testing"
)

func TestAEADAES(t *testing.T) {
	v := testVectors[0]
	nonce := decode(v.adata[0])
	c, err := NewAEADAES(decode(v.key), len(nonce))
	if err != nil {
		t.Fatal(err)
	}
	gpt, gct := decode(v.plaintext), decode(v.output)
	ct := c.Seal(nil, nonce, gpt, nil)
	if !bytes.Equal(gct, ct) {
		t.Errorf("Seal: expected: %x\ngot: %x", gct, ct)
	}
	pt, err := c.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Errorf("Open: %s", err)
	}
	if !bytes.Equal(gpt, pt) {
		t.Errorf("Open: expected: %x\ngot: %x", gpt, pt)
	}
}
