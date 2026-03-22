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
//
// State is column-major: State[col][row]
// Row 0: no shift
// Row 1: shift left by 1
// Row 2: shift left by 2
// Row 3: shift left by 3
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
