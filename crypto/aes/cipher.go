package aes

import "errors"

// encrypt encrypts a single 16-byte block from src into dst
// Algorithm: NIST FIPS 197, Section 5.1 -> Cipher
func (b *block) encrypt(dst, src []byte) error {
	if len(src) != 16 || len(dst) < 16 {
		return errors.New("aes: block must be 16 bytes")
	}

	// Load input bytes into state (column-major)
	var s state
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			s[col][row] = src[col*4+row]
		}
	}

	// Initial round key
	b.addRoundKey(&s, b.roundKeys[0])

	// Main rounds: subBytes -> shiftRows -> mixColumns -> addRoundKey
	for round := 1; round < b.nr; round++ {
		b.subBytes(&s)
		b.shiftRows(&s)
		b.mixColumns(&s)
		b.addRoundKey(&s, b.roundKeys[round])
	}

	// Final round (no mixColumns)
	b.subBytes(&s)
	b.shiftRows(&s)
	b.addRoundKey(&s, b.roundKeys[b.nr])

	// Write state to output (column-major)
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			dst[col*4+row] = s[col][row]
		}
	}
	return nil
}

// decrypt decrypts a single 16-byte block from src into dst
// Algorithm: NIST FIPS 197, Section 5.3 -> InvCipher
func (b *block) decrypt(dst, src []byte) error {
	if len(src) != 16 || len(dst) < 16 {
		return errors.New("aes: block must be 16 bytes")
	}

	// Load input bytes into state (column-major)
	var s state
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			s[col][row] = src[col*4+row]
		}
	}

	// Initial round key (last one)
	b.addRoundKey(&s, b.roundKeys[b.nr])

	// Main rounds: invShiftRows -> invSubBytes -> addRoundKey -> invMixColumns
	for round := b.nr - 1; round >= 1; round-- {
		b.invShiftRows(&s)
		b.invSubBytes(&s)
		b.addRoundKey(&s, b.roundKeys[round])
		b.invMixColumns(&s)
	}

	// Final round (no invMixColumns)
	b.invShiftRows(&s)
	b.invSubBytes(&s)
	b.addRoundKey(&s, b.roundKeys[0])

	// Write state to output (column-major)
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			dst[col*4+row] = s[col][row]
		}
	}
	return nil
}
