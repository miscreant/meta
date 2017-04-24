// Written in 2015 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

// Package siv implements Synthetic Initialization Vector (SIV) authenticated
// encryption using AES (RFC 5297).
package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"hash"

	"github.com/dchest/cmac"
)

const MaxAssociatedDataItems = 126 // maximum number of associated data items

var (
	ErrKeySize                    = errors.New("siv: bad key size")
	ErrNotAuthentic               = errors.New("siv: authentication failed")
	ErrTooManyAssociatedDataItems = errors.New("siv: too many associated data items")
)

type Cipher struct {
	h          hash.Hash
	b          cipher.Block
	tmp1, tmp2 []byte
}

func newCipher(macBlock, ctrBlock cipher.Block) (c *Cipher, err error) {
	c = new(Cipher)
	c.h, err = cmac.New(macBlock)
	if err != nil {
		return nil, err
	}
	c.b = ctrBlock
	c.tmp1 = make([]byte, c.b.BlockSize())
	c.tmp2 = make([]byte, c.b.BlockSize())
	return c, nil
}

// NewAES returns a new AES-SIV cipher with the given key, which must be
// twice as long as an AES key, either 32, 48, or 64 bytes to select AES-128
// (AES-SIV-CMAC-256), AES-192 (AES-SIV-CMAC-384), or AES-256 (AES-SIV-CMAC-512).
func NewAES(key []byte) (c *Cipher, err error) {
	n := len(key)
	if n != 32 && n != 48 && n != 64 {
		return nil, ErrKeySize
	}
	c1, err := aes.NewCipher(key[:n/2])
	if err != nil {
		return nil, err
	}
	c2, err := aes.NewCipher(key[n/2:])
	if err != nil {
		return nil, err
	}
	return newCipher(c1, c2)
}

// Overhead returns the difference between plaintext and ciphertext lengths.
func (c *Cipher) Overhead() int {
	return c.h.Size()
}

// Seal encrypts and authenticates plaintext, authenticates the given
// associated data items, and appends the result to dst, returning the updated
// slice.
//
// The ciphertext and dst may alias exactly or not at all.
//
// For nonce-based encryption, the nonce should be the last associated data item.
func (c *Cipher) Seal(dst []byte, plaintext []byte, data ...[]byte) ([]byte, error) {
	if len(data) > MaxAssociatedDataItems {
		return nil, ErrTooManyAssociatedDataItems
	}

	// Authenticate
	iv := c.s2v(data, plaintext)
	ret, out := sliceForAppend(dst, len(iv)+len(plaintext))
	copy(out, iv)

	// Encrypt
	zeroIVBits(iv)
	ctr := cipher.NewCTR(c.b, iv)
	ctr.XORKeyStream(out[len(iv):], plaintext)

	return ret, nil
}

// Open decrypts ciphertext, authenticates the decrypted plaintext and the given
// associated data items and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The additional data items must match the
// items passed to Seal.
//
// The ciphertext and dst may alias exactly or not at all.
//
// For nonce-based encryption, the nonce should be the last associated data item.
func (c *Cipher) Open(dst []byte, ciphertext []byte, data ...[]byte) ([]byte, error) {
	if len(data) > MaxAssociatedDataItems {
		return nil, ErrTooManyAssociatedDataItems
	}
	if len(ciphertext) < c.Overhead() {
		return nil, ErrNotAuthentic
	}

	// Decrypt
	iv := c.tmp1[:c.Overhead()]
	copy(iv, ciphertext)
	zeroIVBits(iv)
	ctr := cipher.NewCTR(c.b, iv)
	ret, out := sliceForAppend(dst, len(ciphertext)-len(iv))
	ctr.XORKeyStream(out, ciphertext[len(iv):])

	// Authenticate
	expected := c.s2v(data, out)
	if subtle.ConstantTimeCompare(ciphertext[:len(iv)], expected) != 1 {
		zero(out)
		return nil, ErrNotAuthentic
	}
	return ret, nil
}

func (c *Cipher) s2v(s [][]byte, sn []byte) []byte {
	h := c.h
	h.Reset()

	tmp, d := c.tmp1, c.tmp2
	zero(tmp)

	// NOTE(dchest): The standalone S2V returns CMAC(1) if the number of
	// passed vectors is zero, however in SIV contruction this case is
	// never triggered, since we always pass plaintext as the last vector
	// (even if it's zero-length), so we omit this case.

	h.Write(tmp)
	d = h.Sum(d[:0])
	h.Reset()

	for _, v := range s {
		h.Write(v)
		tmp = h.Sum(tmp[:0])
		h.Reset()
		dbl(d)
		xor(d, tmp)
	}

	zero(tmp)

	if len(sn) >= h.BlockSize() {
		n := len(sn) - len(d)
		copy(tmp, sn[n:])
		h.Write(sn[:n])
	} else {
		copy(tmp, sn)
		tmp[len(sn)] = 0x80
		dbl(d)
	}
	xor(tmp, d)
	h.Write(tmp)
	return h.Sum(tmp[:0])
}

func dbl(x []byte) {
	var b byte
	for i := len(x) - 1; i >= 0; i-- {
		bb := x[i] >> 7
		x[i] = x[i]<<1 | b
		b = bb
	}
	x[len(x)-1] ^= byte(subtle.ConstantTimeSelect(int(b), 0x87, 0))
}

func xor(a, b []byte) {
	for i, v := range b {
		a[i] ^= v
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func zeroIVBits(iv []byte) {
	// "We zero-out the top bit in each of the last two 32-bit words
	// of the IV before assigning it to Ctr"
	//  — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
	iv[len(iv)-8] &= 0x7f
	iv[len(iv)-4] &= 0x7f
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
