// Written in 2015 by Dmitry Chestnykh.

package miscreant

import "crypto/cipher"

// aead is a wrapper for Cipher implementing cipher.AEAD interface.
type aead struct {
	c         *Cipher
	nonceSize int
}

// NewAEAD returns an AES-SIV instance implementing cipher.AEAD interface,
// with the given cipher, nonce size, and a key which must be twice as long
// as an AES key, either 32 or 64 bytes to select AES-128 (AES-SIV-256)
// or AES-256 (AES-SIV-512).
//
// Unless the given nonce size is less than zero, Seal and Open will panic when
// passed nonce of a different size.
func NewAEAD(alg string, key []byte, nonceSize int) (cipher.AEAD, error) {
	switch alg {
	case "AES-SIV", "AES-CMAC-SIV":
		c, err := NewAESCMACSIV(key)
		if err != nil {
			return nil, err
		}
		return &aead{c: c, nonceSize: nonceSize}, nil
	case "AES-PMAC-SIV":
		c, err := NewAESPMACSIV(key)
		if err != nil {
			return nil, err
		}
		return &aead{c: c, nonceSize: nonceSize}, nil
	default:
		panic("NewAEAD: unknown cipher: " + alg)
	}
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
