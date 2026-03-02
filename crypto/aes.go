// AES
package crypto

type Word = [4]byte

type State = [4][4]byte

type KeyScheduler interface {
	ExpandKey(key []byte) ([][4]Word, error)
}

type BlockCipher interface {
	SubBytes(state *State)
	ShiftRows(state *State)
	MixColumns(state *State)
	AddRoundKey(state *State, roundKey [4]Word)
	InvSubBytes(state *State)
	InvShiftRows(state *State)
	InvMixColumns(state *State)
}

type AESCipher interface {
	KeySize() int
	NumRounds() int
	BlockSize() int
	Encrypt(dst, src []byte) error
	Decrypt(dst, src []byte) error
}
