package integration

import (
	"bytes"
	"proiect-si/crypto/aes"
	"proiect-si/crypto/ecdh"
	"testing"
)

// handshake performs an X25519 key exchange between two parties and returns
// their shared secret, which is used directly as an AES-256 key.
func handshake(t *testing.T) (aliceKey, bobKey ecdh.KeyExchange, shared [32]byte) {
	t.Helper()
	var alicePub, bobPub *ecdh.PublicKey
	var err error

	aliceKey, alicePub, err = ecdh.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Alice GenerateKeyPair: %v", err)
	}
	bobKey, bobPub, err = ecdh.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Bob GenerateKeyPair: %v", err)
	}

	sharedA, err := aliceKey.DeriveShared(bobPub)
	if err != nil {
		t.Fatalf("Alice DeriveShared: %v", err)
	}
	sharedB, err := bobKey.DeriveShared(alicePub)
	if err != nil {
		t.Fatalf("Bob DeriveShared: %v", err)
	}
	if sharedA != sharedB {
		t.Fatal("shared secrets differ — handshake broken")
	}
	return aliceKey, bobKey, sharedA
}

// TestECDHAESRoundTrip tests the core P2P flow: ECDH handshake → AES-256-CTR
// encrypt on one side → decrypt on the other → plaintext matches.
func TestECDHAESRoundTrip(t *testing.T) {
	_, _, shared := handshake(t)

	cipher, err := aes.NewCTR(shared[:])
	if err != nil {
		t.Fatalf("NewCTR: %v", err)
	}

	plaintext := []byte("hello from the other side of the mesh")
	ciphertext := make([]byte, len(plaintext))
	nonce, err := cipher.Encrypt(ciphertext, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got := make([]byte, len(plaintext))
	if err := cipher.Decrypt(got, ciphertext, nonce); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("roundtrip failed\n got:  %q\n want: %q", got, plaintext)
	}
}

// TestECDHAESSeparateCiphers tests that Alice and Bob derive separate AES
// instances from the same shared secret and can still communicate.
func TestECDHAESSeparateCiphers(t *testing.T) {
	_, _, shared := handshake(t)

	aliceCTR, err := aes.NewCTR(shared[:])
	if err != nil {
		t.Fatalf("Alice NewCTR: %v", err)
	}
	bobCTR, err := aes.NewCTR(shared[:])
	if err != nil {
		t.Fatalf("Bob NewCTR: %v", err)
	}

	plaintext := []byte("encrypted p2p message")
	ciphertext := make([]byte, len(plaintext))
	nonce, err := aliceCTR.Encrypt(ciphertext, plaintext)
	if err != nil {
		t.Fatalf("Alice Encrypt: %v", err)
	}

	got := make([]byte, len(plaintext))
	if err := bobCTR.Decrypt(got, ciphertext, nonce); err != nil {
		t.Fatalf("Bob Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("got %q, want %q", got, plaintext)
	}
}

// TestECDHAESBidirectional tests that both parties can send encrypted messages
// to each other using the shared key.
func TestECDHAESBidirectional(t *testing.T) {
	_, _, shared := handshake(t)

	aliceCTR, _ := aes.NewCTR(shared[:])
	bobCTR, _ := aes.NewCTR(shared[:])

	msgs := []struct{ sender, msg string }{
		{"alice", "hey bob"},
		{"bob", "hey alice"},
		{"alice", "how's the mesh going"},
		{"bob", "encrypted and running"},
	}

	for _, m := range msgs {
		src := []byte(m.msg)
		ct := make([]byte, len(src))
		pt := make([]byte, len(src))

		var nonce [12]byte
		var err error
		if m.sender == "alice" {
			nonce, err = aliceCTR.Encrypt(ct, src)
			if err != nil {
				t.Fatalf("alice Encrypt: %v", err)
			}
			if err = bobCTR.Decrypt(pt, ct, nonce); err != nil {
				t.Fatalf("bob Decrypt: %v", err)
			}
		} else {
			nonce, err = bobCTR.Encrypt(ct, src)
			if err != nil {
				t.Fatalf("bob Encrypt: %v", err)
			}
			if err = aliceCTR.Decrypt(pt, ct, nonce); err != nil {
				t.Fatalf("alice Decrypt: %v", err)
			}
		}

		if !bytes.Equal(pt, src) {
			t.Errorf("%s: got %q, want %q", m.sender, pt, src)
		}
	}
}

// TestECDHAESKeyIsolation verifies that two independent ECDH sessions produce
// different shared secrets, so their AES keystreams don't overlap.
func TestECDHAESKeyIsolation(t *testing.T) {
	_, _, shared1 := handshake(t)
	_, _, shared2 := handshake(t)

	if shared1 == shared2 {
		t.Fatal("two independent handshakes produced the same shared secret")
	}

	plaintext := []byte("same plaintext, different keys")

	ctr1, _ := aes.NewCTR(shared1[:])
	ctr2, _ := aes.NewCTR(shared2[:])

	var iv [16]byte
	ctr1Fixed, _ := aes.NewCTRWithIV(shared1[:], iv)
	ctr2Fixed, _ := aes.NewCTRWithIV(shared2[:], iv)

	ct1 := make([]byte, len(plaintext))
	ct2 := make([]byte, len(plaintext))
	nonce1, _ := ctr1Fixed.Encrypt(ct1, plaintext)
	nonce2, _ := ctr2Fixed.Encrypt(ct2, plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Error("different sessions produced identical ciphertext — key isolation broken")
	}

	pt := make([]byte, len(plaintext))
	if err := ctr1.Decrypt(pt, ct1, nonce1); err != nil || !bytes.Equal(pt, plaintext) {
		t.Error("session 1 failed to decrypt its own ciphertext")
	}
	if err := ctr2.Decrypt(pt, ct2, nonce2); err != nil || !bytes.Equal(pt, plaintext) {
		t.Error("session 2 failed to decrypt its own ciphertext")
	}
}

// TestECDHAESLargePayload tests encryption of a larger payload (simulating a
// file chunk) to exercise multi-block CTR mode with an ECDH-derived key.
func TestECDHAESLargePayload(t *testing.T) {
	_, _, shared := handshake(t)

	senderCTR, _ := aes.NewCTR(shared[:])
	receiverCTR, _ := aes.NewCTR(shared[:])

	chunk := make([]byte, 4096)
	for i := range chunk {
		chunk[i] = byte(i)
	}

	ciphertext := make([]byte, len(chunk))
	nonce, err := senderCTR.Encrypt(ciphertext, chunk)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got := make([]byte, len(chunk))
	if err := receiverCTR.Decrypt(got, ciphertext, nonce); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, chunk) {
		t.Error("large payload roundtrip failed")
	}
}
