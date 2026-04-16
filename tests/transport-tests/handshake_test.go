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
		clientKey, clientErr = transport.ClientHandshake(clientConn)
	}()
	go func() {
		defer wg.Done()
		serverKey, serverErr = transport.ServerHandshake(serverConn)
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
		_, err := transport.ClientHandshake(conn)
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

	_, err := transport.ClientHandshake(conn)
	if err == nil {
		t.Fatal("expected error on closed reader, got nil")
	}
}
