package transport

import (
	"crypto/sha256"
	"io"

	"proiect-si/crypto/ecdh"
)

// ClientHandshake and ServerHandshake are identical, names are just for call-site clarity
// both sides generate an ephemeral X25519 keypair, exchange 32-byte pubkeys, derive shared secret
// raw X25519 output is a curve u-coordinate not uniform key material, SHA-256 fixes that
func ClientHandshake(rw io.ReadWriter) ([32]byte, error) { return handshake(rw) }
func ServerHandshake(rw io.ReadWriter) ([32]byte, error) { return handshake(rw) }

func handshake(rw io.ReadWriter) ([32]byte, error) {
	priv, pub, err := ecdh.GenerateKeyPair()
	if err != nil {
		return [32]byte{}, err
	}

	// io.Pipe writes block until the other side reads, sequential write-then-read deadlocks
	// net.Conn is fine (32 bytes fits in kernel buf) but goroutine makes both cases work
	ourPub := pub.Bytes()
	writeErr := make(chan error, 1)
	go func() {
		_, err := rw.Write(ourPub[:])
		writeErr <- err
	}()

	var theirBytes [32]byte
	if _, err := io.ReadFull(rw, theirBytes[:]); err != nil {
		return [32]byte{}, err
	}
	if err := <-writeErr; err != nil {
		return [32]byte{}, err
	}

	shared, err := priv.DeriveShared(ecdh.NewPublicKey(theirBytes))
	if err != nil {
		return [32]byte{}, err
	}

	return sha256.Sum256(shared[:]), nil
}
