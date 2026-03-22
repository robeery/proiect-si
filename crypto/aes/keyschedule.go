package aes

import "errors"

// block is the AES block cipher — holds the round keys derived from the original key
type block struct {
	roundKeys [][4]word
	nk        int // words in the key: 4 for AES-128, 8 for AES-256
	nr        int // number of rounds: 10 for AES-128, 14 for AES-256
}

// newBlock builds an AES block cipher from a 16- or 32-byte key
func newBlock(key []byte) (*block, error) {
	nk := len(key) / 4
	if len(key)%4 != 0 || (nk != 4 && nk != 8) {
		return nil, errors.New("aes: key must be 16 or 32 bytes")
	}
	nr := 6 + nk
	b := &block{nk: nk, nr: nr}
	var err error
	b.roundKeys, err = b.expandKey(key)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// expandKey derives Nr+1 round keys from the original key
// Algorithm: NIST FIPS 197, Section 5.2 -> KeyExpansion
func (b *block) expandKey(key []byte) ([][4]word, error) {
	nk := len(key) / 4
	if len(key)%4 != 0 || (nk != 4 && nk != 8) {
		return nil, errors.New("aes: key must be 16 or 32 bytes")
	}
	nr := 6 + nk
	total := 4 * (nr + 1)

	w := make([]word, total)

	// Copy the original key into the first Nk words
	for i := 0; i < nk; i++ {
		w[i] = word{key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]}
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
	roundKeys := make([][4]word, nr+1)
	for i := 0; i <= nr; i++ {
		roundKeys[i] = [4]word{w[4*i], w[4*i+1], w[4*i+2], w[4*i+3]}
	}
	return roundKeys, nil
}

func (b *block) keySize() int   { return b.nk * 4 }
func (b *block) numRounds() int { return b.nr }
func (b *block) blockSize() int { return 16 }

// rotWord shifts bytes left by one
func rotWord(w word) word {
	return word{w[1], w[2], w[3], w[0]}
}

// subWord runs each byte of a word through the S-box
func subWord(w word) word {
	return word{sbox[w[0]], sbox[w[1]], sbox[w[2]], sbox[w[3]]}
}
