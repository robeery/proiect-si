package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"io"

	"proiect-si/crypto/ecdh"
)

func ClientHandshake(rw io.ReadWriter) ([32]byte, string, error) {
	return handshake(rw)
}

func ServerHandshake(rw io.ReadWriter) ([32]byte, string, error) {
	return handshake(rw)
}

func handshake(rw io.ReadWriter) ([32]byte, string, error) {
	priv, pub, err := ecdh.GenerateKeyPair()
	if err != nil {
		return [32]byte{}, "", err
	}

	ourPub := pub.Bytes()
	writeErr := make(chan error, 1)
	go func() {
		_, err := rw.Write(ourPub[:])
		writeErr <- err
	}()

	var theirBytes [32]byte
	if _, err := io.ReadFull(rw, theirBytes[:]); err != nil {
		return [32]byte{}, "", err
	}
	if err := <-writeErr; err != nil {
		return [32]byte{}, "", err
	}

	shared, err := priv.DeriveShared(ecdh.NewPublicKey(theirBytes))
	if err != nil {
		return [32]byte{}, "", err
	}

	sessionKey := sha256.Sum256(shared[:])
	fingerprint := Fingerprint(theirBytes)
	return sessionKey, fingerprint, nil
}

func Fingerprint(pubKey [32]byte) string {
	h := sha256.Sum256(pubKey[:])
	return hex.EncodeToString(h[:4])
}
