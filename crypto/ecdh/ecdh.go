package ecdh

import (
	"crypto/rand"
	"errors"
)

type scalarMultiplier interface {
	multiply(scalar, point *[32]byte) [32]byte
}

// KeyExchange is the public interface for X25519 Diffie-Hellman key exchange.
// Implemented by *PrivateKey.
type KeyExchange interface {
	DeriveShared(pub *PublicKey) ([32]byte, error)
	Bytes() [32]byte
}

var _ KeyExchange = (*PrivateKey)(nil)

type PrivateKey struct {
	scalar [32]byte
}

type PublicKey struct {
	point [32]byte
}

var basePoint = [32]byte{9}

func GenerateKeyPair() (KeyExchange, *PublicKey, error) {
	priv := &PrivateKey{}
	if _, err := rand.Read(priv.scalar[:]); err != nil {
		return nil, nil, err
	}
	clampScalar(&priv.scalar)
	pub := &PublicKey{point: x25519(&priv.scalar, &basePoint)}
	return priv, pub, nil
}

func (priv *PrivateKey) Bytes() [32]byte { return priv.scalar }
func (pub *PublicKey) Bytes() [32]byte   { return pub.point }

func NewPublicKey(b [32]byte) *PublicKey { return &PublicKey{point: b} }

// PrivateKeyFromScalar builds a PrivateKey from a raw scalar without clamping.
// x25519 will clamp on use. Intended for test vectors.
func PrivateKeyFromScalar(scalar [32]byte) *PrivateKey { return &PrivateKey{scalar: scalar} }

// DeriveShared returns x25519(priv, pub), or an error if the result is the all-zero
// point (low-order point attack).
func (priv *PrivateKey) DeriveShared(pub *PublicKey) ([32]byte, error) {
	result := x25519(&priv.scalar, &pub.point)
	var check byte
	for _, b := range result {
		check |= b
	}
	if check == 0 {
		return [32]byte{}, errors.New("x25519: result is the low-order point")
	}
	return result, nil
}
