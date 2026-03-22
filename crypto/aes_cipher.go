package crypto

import "errors"

// Encrypt encrypts a single 16-byte block from src into dst
// Algorithm: NIST FIPS 197, Section 5.1 -> Cipher
func (a *AES) Encrypt(dst, src []byte) error {
	if len(src) != 16 || len(dst) < 16 {
		return errors.New("aes: block must be 16 bytes")
	}

	// Load input bytes into state (column-major)
	var state State
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			state[col][row] = src[col*4+row]
		}
	}

	// Initial round key
	a.AddRoundKey(&state, a.roundKeys[0])

	// Main rounds: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
	for round := 1; round < a.nr; round++ {
		a.SubBytes(&state)
		a.ShiftRows(&state)
		a.MixColumns(&state)
		a.AddRoundKey(&state, a.roundKeys[round])
	}

	// Final round (no MixColumns)
	a.SubBytes(&state)
	a.ShiftRows(&state)
	a.AddRoundKey(&state, a.roundKeys[a.nr])

	// Write state to output (column-major)
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			dst[col*4+row] = state[col][row]
		}
	}
	return nil
}

// Decrypt decrypts a single 16-byte block from src into dst
// Algorithm: NIST FIPS 197, Section 5.3 -> InvCipher
func (a *AES) Decrypt(dst, src []byte) error {
	if len(src) != 16 || len(dst) < 16 {
		return errors.New("aes: block must be 16 bytes")
	}

	// Load input bytes into state (column-major)
	var state State
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			state[col][row] = src[col*4+row]
		}
	}

	// Initial round key (last one)
	a.AddRoundKey(&state, a.roundKeys[a.nr])

	// Main rounds: InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
	for round := a.nr - 1; round >= 1; round-- {
		a.InvShiftRows(&state)
		a.InvSubBytes(&state)
		a.AddRoundKey(&state, a.roundKeys[round])
		a.InvMixColumns(&state)
	}

	// Final round (no InvMixColumns)
	a.InvShiftRows(&state)
	a.InvSubBytes(&state)
	a.AddRoundKey(&state, a.roundKeys[0])

	// Write state to output (column-major)
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			dst[col*4+row] = state[col][row]
		}
	}
	return nil
}
