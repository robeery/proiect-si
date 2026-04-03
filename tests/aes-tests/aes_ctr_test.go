package aestests

import (
	"bytes"
	"encoding/hex"
	"proiect-si/crypto/aes"
	"testing"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}
	return b
}

func mustDecodeHex16(t *testing.T, s string) [16]byte {
	t.Helper()
	b := mustDecodeHex(t, s)
	if len(b) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(b))
	}
	return [16]byte(b)
}

var nistVectors = []struct {
	name       string
	key        string
	iv         string
	plaintext  string
	ciphertext string
}{
	{
		name:       "AES-128",
		key:        "2B7E151628AED2A6ABF7158809CF4F3C",
		iv:         "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
		plaintext:  "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
		ciphertext: "874D6191B620E3261BEF6864990DB6CE9806F66B7970FDFF8617187BB9FFFDFF5AE4DF3EDBD5D35E5B4F09020DB03EAB1E031DDA2FBE03D1792170A0F3009CEE",
	},
	{
		name:       "AES-256",
		key:        "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
		iv:         "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
		plaintext:  "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
		ciphertext: "601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C52B0930DAA23DE94CE87017BA2D84988DDFC9C58DB67AADA613C2DD08457941A6",
	},
}

// TestCTREncryptNIST validates CTR encryption against NIST full-message vectors.
func TestCTREncryptNIST(t *testing.T) {
	for _, v := range nistVectors {
		t.Run(v.name, func(t *testing.T) {
			key := mustDecodeHex(t, v.key)
			iv := mustDecodeHex16(t, v.iv)
			plaintext := mustDecodeHex(t, v.plaintext)
			expected := mustDecodeHex(t, v.ciphertext)

			c, err := aes.NewCTRWithIV(key, iv)
			if err != nil {
				t.Fatalf("NewCTRWithIV: %v", err)
			}

			dst := make([]byte, len(plaintext))
			if _, err = c.Encrypt(dst, plaintext); err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			if !bytes.Equal(dst, expected) {
				t.Errorf("ciphertext mismatch\n got:  %X\n want: %X", dst, expected)
			}
		})
	}
}

// TestCTRDecryptNIST validates CTR decryption against NIST full-message vectors.
func TestCTRDecryptNIST(t *testing.T) {
	for _, v := range nistVectors {
		t.Run(v.name, func(t *testing.T) {
			key := mustDecodeHex(t, v.key)
			iv := mustDecodeHex16(t, v.iv)
			ciphertext := mustDecodeHex(t, v.ciphertext)
			expected := mustDecodeHex(t, v.plaintext)

			c, err := aes.NewCTRWithIV(key, iv)
			if err != nil {
				t.Fatalf("NewCTRWithIV: %v", err)
			}

			var nonce [12]byte
			copy(nonce[:], iv[:12])

			dst := make([]byte, len(ciphertext))
			if err = c.Decrypt(dst, ciphertext, nonce); err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if !bytes.Equal(dst, expected) {
				t.Errorf("plaintext mismatch\n got:  %X\n want: %X", dst, expected)
			}
		})
	}
}

// nistBlockVectors tests each 16-byte block in isolation using the exact counter
// value from the NIST document. The IV = shared nonce + per-block counter.
var nistBlockVectors = []struct {
	name       string
	key        string
	iv         string // nonce(12) + counter(4) specific to this block
	plaintext  string // single 16-byte block
	ciphertext string // single 16-byte block
}{
	// AES-128
	{"AES-128/Block1", "2B7E151628AED2A6ABF7158809CF4F3C", "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", "6BC1BEE22E409F96E93D7E117393172A", "874D6191B620E3261BEF6864990DB6CE"},
	{"AES-128/Block2", "2B7E151628AED2A6ABF7158809CF4F3C", "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF00", "AE2D8A571E03AC9C9EB76FAC45AF8E51", "9806F66B7970FDFF8617187BB9FFFDFF"},
	{"AES-128/Block3", "2B7E151628AED2A6ABF7158809CF4F3C", "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF01", "30C81C46A35CE411E5FBC1191A0A52EF", "5AE4DF3EDBD5D35E5B4F09020DB03EAB"},
	{"AES-128/Block4", "2B7E151628AED2A6ABF7158809CF4F3C", "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF02", "F69F2445DF4F9B17AD2B417BE66C3710", "1E031DDA2FBE03D1792170A0F3009CEE"},
	// AES-256
	{"AES-256/Block1", "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", "6BC1BEE22E409F96E93D7E117393172A", "601EC313775789A5B7A7F504BBF3D228"},
	{"AES-256/Block2", "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF00", "AE2D8A571E03AC9C9EB76FAC45AF8E51", "F443E3CA4D62B59ACA84E990CACAF5C5"},
	{"AES-256/Block3", "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF01", "30C81C46A35CE411E5FBC1191A0A52EF", "2B0930DAA23DE94CE87017BA2D84988D"},
	{"AES-256/Block4", "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF02", "F69F2445DF4F9B17AD2B417BE66C3710", "DFC9C58DB67AADA613C2DD08457941A6"},
}

// TestCTRBlocksNIST tests each individual 16-byte block at its specific counter value.
func TestCTRBlocksNIST(t *testing.T) {
	for _, v := range nistBlockVectors {
		t.Run(v.name, func(t *testing.T) {
			key := mustDecodeHex(t, v.key)
			iv := mustDecodeHex16(t, v.iv)
			plaintext := mustDecodeHex(t, v.plaintext)
			expected := mustDecodeHex(t, v.ciphertext)

			c, err := aes.NewCTRWithIV(key, iv)
			if err != nil {
				t.Fatalf("NewCTRWithIV: %v", err)
			}

			dst := make([]byte, len(plaintext))
			if _, err = c.Encrypt(dst, plaintext); err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			if !bytes.Equal(dst, expected) {
				t.Errorf("ciphertext mismatch\n got:  %X\n want: %X", dst, expected)
			}
		})
	}
}

// TestCTRRoundTrip verifies Decrypt(Encrypt(msg)) == msg with a random nonce.
func TestCTRRoundTrip(t *testing.T) {
	keys := []struct {
		name string
		hex  string
	}{
		{"AES-128", "2B7E151628AED2A6ABF7158809CF4F3C"},
		{"AES-256", "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4"},
	}

	plaintext := []byte("hello, AES-CTR round-trip test!")

	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			key := mustDecodeHex(t, k.hex)

			c, err := aes.NewCTR(key)
			if err != nil {
				t.Fatalf("NewCTR: %v", err)
			}

			ciphertext := make([]byte, len(plaintext))
			nonce, err := c.Encrypt(ciphertext, plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			decrypted := make([]byte, len(ciphertext))
			if err = c.Decrypt(decrypted, ciphertext, nonce); err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("round-trip mismatch\n got:  %s\n want: %s", decrypted, plaintext)
			}
		})
	}
}

// TestCTRPartialBlocks verifies round-trips for lengths that produce partial last blocks.
func TestCTRPartialBlocks(t *testing.T) {
	keys := []struct {
		name string
		hex  string
	}{
		{"AES-128", "2B7E151628AED2A6ABF7158809CF4F3C"},
		{"AES-256", "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4"},
	}

	lengths := []int{1, 15, 17, 31}

	src := make([]byte, 32)
	for i := range src {
		src[i] = byte(i)
	}

	for _, k := range keys {
		for _, n := range lengths {
			t.Run(k.name+"/"+string(rune('0'+n/10))+string(rune('0'+n%10))+"bytes", func(t *testing.T) {
				key := mustDecodeHex(t, k.hex)
				plaintext := src[:n]

				c, err := aes.NewCTR(key)
				if err != nil {
					t.Fatalf("NewCTR: %v", err)
				}

				ciphertext := make([]byte, n)
				nonce, err := c.Encrypt(ciphertext, plaintext)
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}

				decrypted := make([]byte, n)
				if err = c.Decrypt(decrypted, ciphertext, nonce); err != nil {
					t.Fatalf("Decrypt: %v", err)
				}

				if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("round-trip mismatch for %d bytes", n)
				}
			})
		}
	}
}

// TestCTRErrors verifies that invalid inputs are rejected.
func TestCTRErrors(t *testing.T) {
	validKey128 := mustDecodeHex(t, "2B7E151628AED2A6ABF7158809CF4F3C")
	validIV := mustDecodeHex16(t, "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF")

	t.Run("NewCTR/key15bytes", func(t *testing.T) {
		if _, err := aes.NewCTR(make([]byte, 15)); err == nil {
			t.Error("expected error for 15-byte key")
		}
	})

	t.Run("NewCTR/key24bytes", func(t *testing.T) {
		if _, err := aes.NewCTR(make([]byte, 24)); err == nil {
			t.Error("expected error for 24-byte key (AES-192 not supported)")
		}
	})

	t.Run("NewCTRWithIV/key15bytes", func(t *testing.T) {
		if _, err := aes.NewCTRWithIV(make([]byte, 15), validIV); err == nil {
			t.Error("expected error for 15-byte key")
		}
	})

	t.Run("Encrypt/dstTooSmall", func(t *testing.T) {
		c, _ := aes.NewCTR(validKey128)
		dst := make([]byte, 4)
		src := make([]byte, 16)
		if _, err := c.Encrypt(dst, src); err == nil {
			t.Error("expected error when dst smaller than src")
		}
	})

	t.Run("Decrypt/dstTooSmall", func(t *testing.T) {
		c, _ := aes.NewCTR(validKey128)
		var nonce [12]byte
		dst := make([]byte, 4)
		src := make([]byte, 16)
		if err := c.Decrypt(dst, src, nonce); err == nil {
			t.Error("expected error when dst smaller than src")
		}
	})
}
