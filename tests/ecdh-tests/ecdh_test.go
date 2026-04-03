package ecdhtests

import (
	"encoding/hex"
	"proiect-si/crypto/ecdh"
	"testing"
)

func mustDecodeHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode error: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// TestX25519Vectors checks the two RFC 7748 §6.1 scalar multiplication test vectors.
func TestX25519Vectors(t *testing.T) {
	vectors := []struct {
		name   string
		scalar string
		uCoord string
		result string
	}{
		{
			name:   "RFC7748 vector 1",
			scalar: "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
			uCoord: "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
			result: "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
		},
		{
			name:   "RFC7748 vector 2",
			scalar: "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
			uCoord: "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413",
			result: "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			scalar := mustDecodeHex32(t, v.scalar)
			uCoord := mustDecodeHex32(t, v.uCoord)
			want := mustDecodeHex32(t, v.result)

			priv := ecdh.PrivateKeyFromScalar(scalar)
			pub := ecdh.NewPublicKey(uCoord)

			got, err := priv.DeriveShared(pub)
			if err != nil {
				t.Fatalf("DeriveShared error: %v", err)
			}
			if got != want {
				t.Errorf("result mismatch\n got:  %x\n want: %x", got, want)
			}
		})
	}
}

// TestECDHRoundTrip verifies the two-party ECDH exchange using RFC 7748 §6.1 vectors
// and also tests with freshly generated key pairs.
func TestECDHRoundTrip(t *testing.T) {
	bobScalar := mustDecodeHex32(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPubExpected := mustDecodeHex32(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	alicePubRFC := mustDecodeHex32(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	wantShared := mustDecodeHex32(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	basePoint := ecdh.NewPublicKey([32]byte{9})
	bobPriv := ecdh.PrivateKeyFromScalar(bobScalar)

	bobPubComputed, err := bobPriv.DeriveShared(basePoint)
	if err != nil {
		t.Fatalf("Bob pubkey derivation error: %v", err)
	}
	if bobPubComputed != bobPubExpected {
		t.Errorf("Bob public key mismatch\n got:  %x\n want: %x", bobPubComputed, bobPubExpected)
	}

	alicePub := ecdh.NewPublicKey(alicePubRFC)
	sharedBA, err := bobPriv.DeriveShared(alicePub)
	if err != nil {
		t.Fatalf("Bob DeriveShared error: %v", err)
	}
	if sharedBA != wantShared {
		t.Errorf("Bob shared mismatch\n got:  %x\n want: %x", sharedBA, wantShared)
	}

	t.Run("random keypair roundtrip", func(t *testing.T) {
		alice, alicePub2, err := ecdh.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair error: %v", err)
		}
		bob, bobPub2, err := ecdh.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair error: %v", err)
		}

		sAB, err := alice.DeriveShared(bobPub2)
		if err != nil {
			t.Fatalf("DeriveShared error: %v", err)
		}
		sBA, err := bob.DeriveShared(alicePub2)
		if err != nil {
			t.Fatalf("DeriveShared error: %v", err)
		}

		if sAB != sBA {
			t.Errorf("shared secrets differ\n alice→bob: %x\n bob→alice: %x", sAB, sBA)
		}
	})
}

// TestLowOrderPointRejection verifies that DeriveShared rejects the all-zero point.
func TestLowOrderPointRejection(t *testing.T) {
	_, pub, err := ecdh.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	zeroPub := ecdh.NewPublicKey([32]byte{})

	priv := ecdh.PrivateKeyFromScalar(pub.Bytes())
	_, err = priv.DeriveShared(zeroPub)
	if err == nil {
		t.Error("expected error for low-order point, got nil")
	}
}
