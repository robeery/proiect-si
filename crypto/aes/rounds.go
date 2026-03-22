package aes

// subBytes replaces each byte in the state with its S-box substitute
// Algorithm: NIST FIPS 197, Section 5.1.1 -> SubBytes
func (b *block) subBytes(s *state) {
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			s[col][row] = sbox[s[col][row]]
		}
	}
}

// shiftRows rotates each row left by its row index (0, 1, 2, 3)
// Algorithm: NIST FIPS 197, Section 5.1.2 -> ShiftRows

// state is column-major: state[col][row]
func (b *block) shiftRows(s *state) {
	// Row 1: shift left by 1
	s[0][1], s[1][1], s[2][1], s[3][1] =
		s[1][1], s[2][1], s[3][1], s[0][1]

	// Row 2: shift left by 2
	s[0][2], s[1][2], s[2][2], s[3][2] =
		s[2][2], s[3][2], s[0][2], s[1][2]

	// Row 3: shift left by 3 (= shift right by 1)
	s[0][3], s[1][3], s[2][3], s[3][3] =
		s[3][3], s[0][3], s[1][3], s[2][3]
}

// mixColumns multiplies each column by a fixed matrix in GF(2^8)
// Algorithm: NIST FIPS 197, Section 5.1.3 -> MixColumns

// Matrix:
//
//	[2 3 1 1]
//	[1 2 3 1]
//	[1 1 2 3]
//	[3 1 1 2]
func (b *block) mixColumns(s *state) {
	for col := 0; col < 4; col++ {
		s0 := s[col][0]
		s1 := s[col][1]
		s2 := s[col][2]
		s3 := s[col][3]

		s[col][0] = gfMul(2, s0) ^ gfMul(3, s1) ^ s2 ^ s3
		s[col][1] = s0 ^ gfMul(2, s1) ^ gfMul(3, s2) ^ s3
		s[col][2] = s0 ^ s1 ^ gfMul(2, s2) ^ gfMul(3, s3)
		s[col][3] = gfMul(3, s0) ^ s1 ^ s2 ^ gfMul(2, s3)
	}
}

// addRoundKey XORs the state with a round key
// Algorithm: NIST FIPS 197, Section 5.1.4 -> AddRoundKey
func (b *block) addRoundKey(s *state, roundKey [4]word) {
	for col := 0; col < 4; col++ {
		s[col][0] ^= roundKey[col][0]
		s[col][1] ^= roundKey[col][1]
		s[col][2] ^= roundKey[col][2]
		s[col][3] ^= roundKey[col][3]
	}
}

// invSubBytes replaces each byte in the state with its inverse S-box substitute
// Algorithm: NIST FIPS 197, Section 5.3.2 -> InvSubBytes
func (b *block) invSubBytes(s *state) {
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			s[col][row] = invSbox[s[col][row]]
		}
	}
}

// invShiftRows rotates each row right by its row index (0, 1, 2, 3)
// Algorithm: NIST FIPS 197, Section 5.3.1 -> InvShiftRows
func (b *block) invShiftRows(s *state) {
	// Row 1: shift right by 1
	s[0][1], s[1][1], s[2][1], s[3][1] =
		s[3][1], s[0][1], s[1][1], s[2][1]

	// Row 2: shift right by 2
	s[0][2], s[1][2], s[2][2], s[3][2] =
		s[2][2], s[3][2], s[0][2], s[1][2]

	// Row 3: shift right by 3 (= shift left by 1)
	s[0][3], s[1][3], s[2][3], s[3][3] =
		s[1][3], s[2][3], s[3][3], s[0][3]
}

// invMixColumns multiplies each column by the inverse matrix in GF(2^8)
// Algorithm: NIST FIPS 197, Section 5.3.3 -> InvMixColumns
//
// Inverse matrix:
//
//	[14 11 13  9]
//	[ 9 14 11 13]
//	[13  9 14 11]
//	[11 13  9 14]
func (b *block) invMixColumns(s *state) {
	for col := 0; col < 4; col++ {
		s0 := s[col][0]
		s1 := s[col][1]
		s2 := s[col][2]
		s3 := s[col][3]

		s[col][0] = gfMul(14, s0) ^ gfMul(11, s1) ^ gfMul(13, s2) ^ gfMul(9, s3)
		s[col][1] = gfMul(9, s0) ^ gfMul(14, s1) ^ gfMul(11, s2) ^ gfMul(13, s3)
		s[col][2] = gfMul(13, s0) ^ gfMul(9, s1) ^ gfMul(14, s2) ^ gfMul(11, s3)
		s[col][3] = gfMul(11, s0) ^ gfMul(13, s1) ^ gfMul(9, s2) ^ gfMul(14, s3)
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
		// Save the high bit before shifting (it overflows out of the byte)
		hi := b & 0x80
		// Multiply b by x (shift left)
		b <<= 1
		// Reduce modulo the AES polynomial 0x11B if the high bit was set
		if hi != 0 {
			b ^= 0x1b
		}
		// Next bit of a
		a >>= 1
	}
	return res
}
