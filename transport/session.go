package transport

import (
	"errors"
	"io"

	"proiect-si/crypto/aes"
)

// ErrShortFrame is returned when a frame body is too short to hold a 12-byte nonce
var ErrShortFrame = errors.New("transport: frame too short to contain nonce")

// Session encrypts and decrypts messages over an io.Reader/Writer pair
// uses the session key from the ECDH handshake, fresh nonce per message
type Session struct {
	cipher aes.Cipher
}

func NewSession(key [32]byte) (*Session, error) {
	c, err := aes.NewCTR(key[:])
	if err != nil {
		return nil, err
	}
	return &Session{cipher: c}, nil
}

// WriteMessage encrypts plaintext and writes it as one framed message
// frame body layout: nonce(12) | ciphertext
func (s *Session) WriteMessage(w io.Writer, plaintext []byte) error {
	ct := make([]byte, len(plaintext))
	nonce, err := s.cipher.Encrypt(ct, plaintext)
	if err != nil {
		return err
	}
	body := make([]byte, 12+len(ct))
	copy(body[:12], nonce[:])
	copy(body[12:], ct)
	return WriteFrame(w, body)
}

// ReadMessage reads one framed message and returns decrypted plaintext
func (s *Session) ReadMessage(r io.Reader) ([]byte, error) {
	body, err := ReadFrame(r)
	if err != nil {
		return nil, err
	}
	if len(body) < 12 {
		return nil, ErrShortFrame
	}
	var nonce [12]byte
	copy(nonce[:], body[:12])
	ct := body[12:]
	pt := make([]byte, len(ct))
	if err := s.cipher.Decrypt(pt, ct, nonce); err != nil {
		return nil, err
	}
	return pt, nil
}
