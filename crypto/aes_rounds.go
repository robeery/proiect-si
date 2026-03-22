package crypto

// SubBytes replaces each byte in the state with its S-box substitute
// Algorithm: NIST FIPS 197, Section 5.1.1 -> SubBytes
func (a *AES) SubBytes(state *State) {
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			state[col][row] = sbox[state[col][row]]
		}
	}
}

// ShiftRows rotates each row left by its row index (0, 1, 2, 3)
// Algorithm: NIST FIPS 197, Section 5.1.2 -> ShiftRows

// State is column-major: State[col][row]
func (a *AES) ShiftRows(state *State) {
	// Row 1: shift left by 1
	state[0][1], state[1][1], state[2][1], state[3][1] =
		state[1][1], state[2][1], state[3][1], state[0][1]

	// Row 2: shift left by 2
	state[0][2], state[1][2], state[2][2], state[3][2] =
		state[2][2], state[3][2], state[0][2], state[1][2]

	// Row 3: shift left by 3 (= shift right by 1)
	state[0][3], state[1][3], state[2][3], state[3][3] =
		state[3][3], state[0][3], state[1][3], state[2][3]
}

// MixColumns multiplies each column by a fixed matrix in GF(2^8)
// Algorithm: NIST FIPS 197, Section 5.1.3 -> MixColumns

// Matrix:
//
//	[2 3 1 1]
//	[1 2 3 1]
//	[1 1 2 3]
//	[3 1 1 2]
func (a *AES) MixColumns(state *State) {
	for col := 0; col < 4; col++ {
		s0 := state[col][0]
		s1 := state[col][1]
		s2 := state[col][2]
		s3 := state[col][3]

		state[col][0] = gfMul(2, s0) ^ gfMul(3, s1) ^ s2 ^ s3
		state[col][1] = s0 ^ gfMul(2, s1) ^ gfMul(3, s2) ^ s3
		state[col][2] = s0 ^ s1 ^ gfMul(2, s2) ^ gfMul(3, s3)
		state[col][3] = gfMul(3, s0) ^ s1 ^ s2 ^ gfMul(2, s3)
	}
}

// AddRoundKey XORs the state with a round key
// Algorithm: NIST FIPS 197, Section 5.1.4 -> AddRoundKey
func (a *AES) AddRoundKey(state *State, roundKey [4]Word) {
	for col := 0; col < 4; col++ {
		state[col][0] ^= roundKey[col][0]
		state[col][1] ^= roundKey[col][1]
		state[col][2] ^= roundKey[col][2]
		state[col][3] ^= roundKey[col][3]
	}
}

// gfMul multiplies two bytes in GF(2^8) with irreducible polynomial 0x11B
// Algorithm: NIST FIPS 197, Section 4.2 -> Multiplication
// ***Note: addition in GF(2^8) is just XOR (the ^ operator)
func gfMul(a, b byte) byte {
	var res byte
	for a > 0 {
		// If the low bit of a is set, add b to the result
		if a&1 != 0 {
			res ^= b
		}
		// Multiply b by x (shift left)
		b <<= 1
		// Reduce modulo the AES polynomial 0x11B
		if b&0x80 != 0 {
			b ^= 0x1b
		}
		// Next bit of a
		a >>= 1
	}
	return res
}
