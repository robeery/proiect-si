package aes

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// CTR is the standard interface for AES encryption in this project.
// It wraps the AES block cipher in CTR (Counter) mode, producing a keystream
// that is XORed with plaintext — supports arbitrary-length input.
type CTR struct {
	cipher *block
}

// NewCTR creates a CTR stream cipher from a 16- or 32-byte key.
func NewCTR(key []byte) (*CTR, error) {
	b, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	return &CTR{cipher: b}, nil
}

// Encrypt encrypts src into dst using a freshly generated 12-byte nonce.
// dst must be at least len(src) bytes.
// The returned nonce must be passed to Decrypt.
func (c *CTR) Encrypt(dst, src []byte) (nonce [12]byte, err error) {
	if _, err = rand.Read(nonce[:]); err != nil {
		return nonce, errors.New("aes-ctr: failed to generate nonce")
	}
	err = c.xorKeystream(dst, src, nonce)
	return nonce, err
}

// Decrypt decrypts src into dst using the nonce returned by Encrypt.
// dst must be at least len(src) bytes.
func (c *CTR) Decrypt(dst, src []byte, nonce [12]byte) error {
	return c.xorKeystream(dst, src, nonce)
}

// xorKeystream XORs src into dst using AES-CTR starting at counter=0.
// Counter block layout: [ nonce(12 bytes) | counter(4 bytes big-endian) ]
func (c *CTR) xorKeystream(dst, src []byte, nonce [12]byte) error {
	if len(dst) < len(src) {
		return errors.New("aes-ctr: dst too small")
	}

	var counterBlock [16]byte
	copy(counterBlock[:12], nonce[:])

	var keystream [16]byte
	var counter uint32

	for len(src) > 0 {
		binary.BigEndian.PutUint32(counterBlock[12:], counter)

		if err := c.cipher.encrypt(keystream[:], counterBlock[:]); err != nil {
			return err
		}

		n := len(src)
		if n > 16 {
			n = 16
		}
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ keystream[i]
		}

		src = src[n:]
		dst = dst[n:]
		counter++
	}
	return nil
}
