package ecdhtests

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"proiect-si/crypto/ecdh"
	"testing"
)

// opensslAvailable reports whether the openssl binary supports X25519.
func opensslAvailable(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		return false
	}
	cmd := exec.Command("openssl", "genpkey", "-algorithm", "X25519")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// opensslGenKey generates a new X25519 private key and returns it as PEM bytes.
func opensslGenKey(t *testing.T) []byte {
	t.Helper()
	out, err := exec.Command("openssl", "genpkey", "-algorithm", "X25519").Output()
	if err != nil {
		t.Fatalf("openssl genpkey: %v", err)
	}
	return out
}

// opensslRawPriv extracts the 32-byte raw scalar from an X25519 PEM private key.
// The PKCS#8 DER encoding for X25519 is 48 bytes; the raw key occupies bytes [16:48].
func opensslRawPriv(t *testing.T, privPEM []byte) [32]byte {
	t.Helper()
	cmd := exec.Command("openssl", "pkey", "-outform", "DER")
	cmd.Stdin = bytes.NewReader(privPEM)
	der, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl pkey (priv DER): %v", err)
	}
	if len(der) != 48 {
		t.Fatalf("expected 48-byte PKCS#8 DER, got %d", len(der))
	}
	var out [32]byte
	copy(out[:], der[16:])
	return out
}

// opensslRawPub extracts the 32-byte raw public key from an X25519 PEM private key.
// The SubjectPublicKeyInfo DER encoding for X25519 is 44 bytes; raw pub is bytes [12:44].
func opensslRawPub(t *testing.T, privPEM []byte) [32]byte {
	t.Helper()
	cmd := exec.Command("openssl", "pkey", "-pubout", "-outform", "DER")
	cmd.Stdin = bytes.NewReader(privPEM)
	der, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl pkey (pub DER): %v", err)
	}
	if len(der) != 44 {
		t.Fatalf("expected 44-byte SPKI DER, got %d", len(der))
	}
	var out [32]byte
	copy(out[:], der[12:])
	return out
}

// opensslPubPEM converts a private key PEM to a public key PEM.
func opensslPubPEM(t *testing.T, privPEM []byte) []byte {
	t.Helper()
	cmd := exec.Command("openssl", "pkey", "-pubout")
	cmd.Stdin = bytes.NewReader(privPEM)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl pkey -pubout: %v", err)
	}
	return out
}

// opensslDeriveShared computes the X25519 shared secret between privPEM and peerPubPEM
// using openssl pkeyutl -derive via temporary files.
func opensslDeriveShared(t *testing.T, privPEM, peerPubPEM []byte) [32]byte {
	t.Helper()

	privFile, err := os.CreateTemp("", "x25519_priv_*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(privFile.Name())
	privFile.Write(privPEM)
	privFile.Close()

	pubFile, err := os.CreateTemp("", "x25519_pub_*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(pubFile.Name())
	pubFile.Write(peerPubPEM)
	pubFile.Close()

	out, err := exec.Command(
		"openssl", "pkeyutl", "-derive",
		"-inkey", privFile.Name(),
		"-peerkey", pubFile.Name(),
	).Output()
	if err != nil {
		t.Fatalf("openssl pkeyutl -derive: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("expected 32-byte shared secret, got %d", len(out))
	}
	var result [32]byte
	copy(result[:], out)
	return result
}

// TestOpenSSLPublicKeyDerivation verifies that our implementation derives the same
// public key from a given private scalar as OpenSSL does, across multiple random keys.
func TestOpenSSLPublicKeyDerivation(t *testing.T) {
	if !opensslAvailable(t) {
		t.Skip("openssl not available or does not support X25519")
	}

	base := ecdh.NewPublicKey([32]byte{9})

	for i := 0; i < 5; i++ {
		privPEM := opensslGenKey(t)
		rawPriv := opensslRawPriv(t, privPEM)
		rawPub := opensslRawPub(t, privPEM)

		priv := ecdh.PrivateKeyFromScalar(rawPriv)
		ourPub, err := priv.DeriveShared(base)
		if err != nil {
			t.Fatalf("iter %d: DeriveShared (pubkey): %v", i, err)
		}
		if ourPub != rawPub {
			t.Errorf("iter %d: public key mismatch\n our: %x\n ssl: %x", i, ourPub, rawPub)
		} else {
			t.Logf("iter %d OK  pub=%s", i, hex.EncodeToString(ourPub[:]))
		}
	}
}

// TestOpenSSLSharedSecret verifies that our ECDH shared secret matches OpenSSL's
// for freshly generated random key pairs.
func TestOpenSSLSharedSecret(t *testing.T) {
	if !opensslAvailable(t) {
		t.Skip("openssl not available or does not support X25519")
	}

	for i := 0; i < 5; i++ {
		alicePEM := opensslGenKey(t)
		bobPEM := opensslGenKey(t)

		aliceRawPriv := opensslRawPriv(t, alicePEM)
		bobRawPriv := opensslRawPriv(t, bobPEM)
		bobRawPub := opensslRawPub(t, bobPEM)
		aliceRawPub := opensslRawPub(t, alicePEM)

		bobPubPEM := opensslPubPEM(t, bobPEM)
		alicePubPEM := opensslPubPEM(t, alicePEM)

		sslSharedAB := opensslDeriveShared(t, alicePEM, bobPubPEM)
		sslSharedBA := opensslDeriveShared(t, bobPEM, alicePubPEM)

		alicePriv := ecdh.PrivateKeyFromScalar(aliceRawPriv)
		bobPriv := ecdh.PrivateKeyFromScalar(bobRawPriv)
		bobPub := ecdh.NewPublicKey(bobRawPub)
		alicePub := ecdh.NewPublicKey(aliceRawPub)

		ourSharedAB, err := alicePriv.DeriveShared(bobPub)
		if err != nil {
			t.Fatalf("iter %d: DeriveShared A→B: %v", i, err)
		}
		ourSharedBA, err := bobPriv.DeriveShared(alicePub)
		if err != nil {
			t.Fatalf("iter %d: DeriveShared B→A: %v", i, err)
		}

		if ourSharedAB != sslSharedAB {
			t.Errorf("iter %d: A→B mismatch\n our: %x\n ssl: %x", i, ourSharedAB, sslSharedAB)
		}
		if ourSharedBA != sslSharedBA {
			t.Errorf("iter %d: B→A mismatch\n our: %x\n ssl: %x", i, ourSharedBA, sslSharedBA)
		}
		if sslSharedAB != sslSharedBA {
			t.Errorf("iter %d: OpenSSL sides disagree — something is wrong with the test", i)
		}

		t.Logf("iter %d OK  shared=%s", i, hex.EncodeToString(sslSharedAB[:]))
	}
}
