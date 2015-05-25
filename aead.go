// Written in 2015 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

package siv

import "crypto/cipher"

// aead is a wrapper for Cipher implementing cipher.AEAD interface.
type aead struct {
	c         *Cipher
	nonceSize int
}

// NewAEADAES returns an AES-SIV instance implementing cipher.AEAD interface,
// with the given nonce size and a key which must be twice as long as an AES key,
// either 32, 48, or 64 bytes to select AES-128 (AES-SIV-CMAC-256), AES-192
// (AES-SIV-CMAC-384), or AES-256 (AES-SIV-CMAC-512).
//
// Unless the given nonce size is less than zero, Seal and Open will panic when
// passed nonce of a different size.
func NewAEADAES(key []byte, nonceSize int) (cipher.AEAD, error) {
	c, err := NewAES(key)
	if err != nil {
		return nil, err
	}
	return &aead{c: c, nonceSize: nonceSize}, nil
}

func (a *aead) NonceSize() int { return a.nonceSize }
func (a *aead) Overhead() int  { return a.c.Overhead() }

func (a *aead) Seal(dst, nonce, plaintext, data []byte) (out []byte) {
	if len(nonce) != a.nonceSize && a.nonceSize >= 0 {
		panic("siv.AEAD: incorrect nonce length")
	}
	var err error
	if data == nil {
		out, err = a.c.Seal(dst, plaintext, nonce)
	} else {
		out, err = a.c.Seal(dst, plaintext, data, nonce)
	}
	if err != nil {
		panic("siv.AEAD: " + err.Error())
	}
	return out
}

func (a *aead) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != a.nonceSize && a.nonceSize >= 0 {
		panic("siv.AEAD: incorrect nonce length")
	}
	if data == nil {
		return a.c.Open(dst, ciphertext, nonce)
	}
	return a.c.Open(dst, ciphertext, data, nonce)
}
