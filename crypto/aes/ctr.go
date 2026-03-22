package aes

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

type CTR struct {
	cipher         *block
	fixedNonce     *[12]byte // nil = generate randomly per Encrypt call
	initialCounter uint32
}

func NewCTR(key []byte) (*CTR, error) {
	b, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	return &CTR{cipher: b}, nil
}

func NewCTRWithIV(key []byte, iv [16]byte) (*CTR, error) {
	b, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	nonce := new([12]byte)
	copy(nonce[:], iv[:12])
	initialCounter := binary.BigEndian.Uint32(iv[12:])
	return &CTR{cipher: b, fixedNonce: nonce, initialCounter: initialCounter}, nil
}

func (c *CTR) Encrypt(dst, src []byte) (nonce [12]byte, err error) {
	if c.fixedNonce != nil {
		nonce = *c.fixedNonce
		err = c.xorKeystream(dst, src, nonce, c.initialCounter)
		return nonce, err
	}
	if _, err = rand.Read(nonce[:]); err != nil {
		return nonce, errors.New("aes-ctr: failed to generate nonce")
	}
	err = c.xorKeystream(dst, src, nonce, 0)
	return nonce, err
}

func (c *CTR) Decrypt(dst, src []byte, nonce [12]byte) error {
	return c.xorKeystream(dst, src, nonce, c.initialCounter)
}

func (c *CTR) xorKeystream(dst, src []byte, nonce [12]byte, initialCounter uint32) error {
	if len(dst) < len(src) {
		return errors.New("aes-ctr: dst too small")
	}

	var counterBlock [16]byte
	copy(counterBlock[:12], nonce[:])

	var keystream [16]byte
	counter := initialCounter

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
