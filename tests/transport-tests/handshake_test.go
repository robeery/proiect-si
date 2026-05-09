package transporttests

import (
	"io"
	"proiect-si/transport"
	"sync"
	"testing"
)

// runHandshakePair runs client and server handshakes concurrently over a pipe
func runHandshakePair(t *testing.T) (clientKey, serverKey [32]byte) {
	t.Helper()
	clientConn, serverConn := newPipeConn()
	defer clientConn.close()
	defer serverConn.close()

	var clientErr, serverErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientKey, _, clientErr = transport.ClientHandshake(clientConn)
	}()
	go func() {
		defer wg.Done()
		serverKey, _, serverErr = transport.ServerHandshake(serverConn)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client handshake: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}
	return
}

func TestHandshakeSymmetric(t *testing.T) {
	clientKey, serverKey := runHandshakePair(t)
	if clientKey != serverKey {
		t.Fatalf("keys differ:\n client: %x\n server: %x", clientKey, serverKey)
	}
}

func TestHandshakeKeyIsNonZero(t *testing.T) {
	clientKey, _ := runHandshakePair(t)
	var zero [32]byte
	if clientKey == zero {
		t.Fatal("derived session key is all-zero")
	}
}

func TestHandshakeEphemeral(t *testing.T) {
	key1, _ := runHandshakePair(t)
	key2, _ := runHandshakePair(t)
	if key1 == key2 {
		t.Fatal("two independent handshakes produced the same session key")
	}
}

func TestHandshakeTruncatedPeer(t *testing.T) {
	r, w := io.Pipe()
	conn := struct {
		io.Reader
		io.Writer
	}{r, io.Discard}

	errCh := make(chan error, 1)
	go func() {
		_, _, err := transport.ClientHandshake(conn)
		errCh <- err
	}()

	// send only 16 bytes then close, simulates peer sending a truncated pubkey
	w.Write(make([]byte, 16))
	w.Close()

	if err := <-errCh; err == nil {
		t.Fatal("expected error for truncated peer pubkey, got nil")
	}
}

func TestHandshakeClosedReader(t *testing.T) {
	r, w := io.Pipe()
	r.Close()
	conn := struct {
		io.Reader
		io.Writer
	}{r, io.Discard}
	_ = w

	_, _, err := transport.ClientHandshake(conn)
	if err == nil {
		t.Fatal("expected error on closed reader, got nil")
	}
}

func TestHandshakeReturnsFingerprint(t *testing.T) {
	clientConn, serverConn := newPipeConn()
	defer clientConn.close()
	defer serverConn.close()

	var clientFP, serverFP string
	var clientErr, serverErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, clientFP, clientErr = transport.ClientHandshake(clientConn)
	}()
	go func() {
		defer wg.Done()
		_, serverFP, serverErr = transport.ServerHandshake(serverConn)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client handshake: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}
	if len(clientFP) != 8 {
		t.Fatalf("client fingerprint length: got %d want 8", len(clientFP))
	}
	if len(serverFP) != 8 {
		t.Fatalf("server fingerprint length: got %d want 8", len(serverFP))
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	fp1 := transport.Fingerprint(key)
	fp2 := transport.Fingerprint(key)
	if fp1 != fp2 {
		t.Fatalf("fingerprint not deterministic: %q != %q", fp1, fp2)
	}
}

func TestFingerprintDifferent(t *testing.T) {
	key1 := [32]byte{1}
	key2 := [32]byte{2}
	fp1 := transport.Fingerprint(key1)
	fp2 := transport.Fingerprint(key2)
	if fp1 == fp2 {
		t.Fatalf("different keys produced same fingerprint: %q", fp1)
	}
}
