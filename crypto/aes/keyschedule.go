package aes

import "errors"

// AES cipher - holds the round keys derived from the original key
type AES struct {
	roundKeys [][4]Word
	nk        int // words in the key: 4 for AES-128, 8 for AES-256
	nr        int // number of rounds: 10 for AES-128, 14 for AES-256
}

// NewAES builds an AES cipher from a 16- or 32-byte key
func NewAES(key []byte) (*AES, error) {
	nk := len(key) / 4
	if len(key)%4 != 0 || (nk != 4 && nk != 8) {
		return nil, errors.New("aes: key must be 16 or 32 bytes")
	}
	nr := 6 + nk
	a := &AES{nk: nk, nr: nr}
	var err error
	a.roundKeys, err = a.ExpandKey(key)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// ExpandKey derives Nr+1 round keys from the original key
// Algorithm: NIST FIPS 197, Section 5.2 -> KeyExpansion
func (a *AES) ExpandKey(key []byte) ([][4]Word, error) {
	nk := len(key) / 4
	if len(key)%4 != 0 || (nk != 4 && nk != 8) {
		return nil, errors.New("aes: key must be 16 or 32 bytes")
	}
	nr := 6 + nk
	total := 4 * (nr + 1)

	w := make([]Word, total)

	// Copy the original key into the first Nk words
	for i := 0; i < nk; i++ {
		w[i] = Word{key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]}
	}

	// Derive the rest one word at a time
	for i := nk; i < total; i++ {
		temp := w[i-1]
		if i%nk == 0 {
			// Every Nk words: rotate, substitute, mix in the round constant
			temp = subWord(rotWord(temp))
			temp[0] ^= rcon[i/nk]
		} else if nk > 6 && i%nk == 4 {
			// AES-256 only: extra substitution halfway through each key block
			temp = subWord(temp)
		}
		w[i][0] = w[i-nk][0] ^ temp[0]
		w[i][1] = w[i-nk][1] ^ temp[1]
		w[i][2] = w[i-nk][2] ^ temp[2]
		w[i][3] = w[i-nk][3] ^ temp[3]
	}

	// Pack every 4 words into one round key
	roundKeys := make([][4]Word, nr+1)
	for i := 0; i <= nr; i++ {
		roundKeys[i] = [4]Word{w[4*i], w[4*i+1], w[4*i+2], w[4*i+3]}
	}
	return roundKeys, nil
}

func (a *AES) KeySize() int   { return a.nk * 4 }
func (a *AES) NumRounds() int { return a.nr }
func (a *AES) BlockSize() int { return 16 }

// rotWord shifts bytes left by one
func rotWord(w Word) Word {
	return Word{w[1], w[2], w[3], w[0]}
}

// subWord runs each byte of a word through the S-box
func subWord(w Word) Word {
	return Word{sbox[w[0]], sbox[w[1]], sbox[w[2]], sbox[w[3]]}
}
