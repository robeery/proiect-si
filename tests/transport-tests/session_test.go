package transporttests

import (
	"bytes"
	"errors"
	"proiect-si/transport"
	"sync"
	"testing"
)

// newSession creates a Session from a handshake-derived key
func newSession(t *testing.T) *transport.Session {
	t.Helper()
	key, _ := runHandshakePair(t)
	s, err := transport.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return s
}

func TestSessionRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"single byte", []byte{0x42}},
		{"sixteen bytes", bytes.Repeat([]byte{0xAB}, 16)},
		{"one KiB", bytes.Repeat([]byte{0xCD}, 1024)},
		{"one MiB", bytes.Repeat([]byte{0xEF}, 1<<20)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSession(t)
			var buf bytes.Buffer
			if err := s.WriteMessage(&buf, tc.payload); err != nil {
				t.Fatalf("WriteMessage: %v", err)
			}
			got, err := s.ReadMessage(&buf)
			if err != nil {
				t.Fatalf("ReadMessage: %v", err)
			}
			if !bytes.Equal(got, tc.payload) {
				t.Fatalf("payload mismatch: got %d bytes want %d", len(got), len(tc.payload))
			}
		})
	}
}

func TestSessionMultipleMessages(t *testing.T) {
	s := newSession(t)
	msgs := [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte(""),
		bytes.Repeat([]byte{0x01}, 300),
		[]byte("last"),
	}
	var buf bytes.Buffer
	for _, m := range msgs {
		if err := s.WriteMessage(&buf, m); err != nil {
			t.Fatalf("WriteMessage: %v", err)
		}
	}
	for i, want := range msgs {
		got, err := s.ReadMessage(&buf)
		if err != nil {
			t.Fatalf("ReadMessage[%d]: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("message %d mismatch", i)
		}
	}
}

// two encryptions of the same plaintext must produce different ciphertext
// because each Encrypt call generates a fresh random nonce
func TestSessionFreshNonce(t *testing.T) {
	s := newSession(t)
	plain := []byte("same plaintext")
	var buf1, buf2 bytes.Buffer
	if err := s.WriteMessage(&buf1, plain); err != nil {
		t.Fatalf("WriteMessage 1: %v", err)
	}
	if err := s.WriteMessage(&buf2, plain); err != nil {
		t.Fatalf("WriteMessage 2: %v", err)
	}
	// raw frame bytes should differ (different nonce each time)
	if bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Fatal("two encryptions of same plaintext produced identical frames")
	}
}

func TestSessionPipe(t *testing.T) {
	clientConn, serverConn := newPipeConn()
	defer clientConn.close()
	defer serverConn.close()

	// run handshake to get a shared key
	var clientKey, serverKey [32]byte
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var err error
		clientKey, err = transport.ClientHandshake(clientConn)
		if err != nil {
			t.Errorf("client handshake: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		var err error
		serverKey, err = transport.ServerHandshake(serverConn)
		if err != nil {
			t.Errorf("server handshake: %v", err)
		}
	}()
	wg.Wait()

	clientSession, err := transport.NewSession(clientKey)
	if err != nil {
		t.Fatalf("NewSession client: %v", err)
	}
	serverSession, err := transport.NewSession(serverKey)
	if err != nil {
		t.Fatalf("NewSession server: %v", err)
	}

	payload := []byte("hello from client over a real pipe")
	errCh := make(chan error, 1)
	go func() { errCh <- clientSession.WriteMessage(clientConn, payload) }()

	got, err := serverSession.ReadMessage(serverConn)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("WriteMessage: %v", writeErr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q want %q", got, payload)
	}
}

func TestSessionShortFrame(t *testing.T) {
	s := newSession(t)
	var buf bytes.Buffer
	// write a frame with only 4 bytes, less than the 12-byte nonce minimum
	if err := transport.WriteFrame(&buf, []byte{0x01, 0x02, 0x03, 0x04}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	_, err := s.ReadMessage(&buf)
	if !errors.Is(err, transport.ErrShortFrame) {
		t.Fatalf("expected ErrShortFrame, got %v", err)
	}
}
