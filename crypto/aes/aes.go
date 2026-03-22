// AES
package aes

type word = [4]byte

type state = [4][4]byte

type KeyScheduler interface {
	expandKey(key []byte) ([][4]word, error)
}

type BlockCipher interface {
	subBytes(s *state)
	shiftRows(s *state)
	mixColumns(s *state)
	addRoundKey(s *state, roundKey [4]word)
	invSubBytes(s *state)
	invShiftRows(s *state)
	invMixColumns(s *state)
	encrypt(dst, src []byte) error
	decrypt(dst, src []byte) error
}

type Cipher interface {
	Encrypt(dst, src []byte) (nonce [12]byte, err error)
	Decrypt(dst, src []byte, nonce [12]byte) error
}
