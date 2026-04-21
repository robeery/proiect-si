package transporttests

import (
	"bytes"
	"fmt"
	"proiect-si/transport"
	"testing"
	"time"
)

// newPeerPair creates a listener on a random port, dials it, and returns
// both ends of the authenticated connection
func newPeerPair(t *testing.T) (client, server *transport.Peer) {
	t.Helper()
	l, err := transport.NewListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer l.Close()

	serverCh := make(chan *transport.Peer, 1)
	go func() { serverCh <- <-l.Accept() }()

	client, err = transport.Dial(l.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	select {
	case server = <-serverCh:
		if server == nil {
			t.Fatal("listener closed before a peer was accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server peer")
	}
	return
}

func TestPeerSendReceive(t *testing.T) {
	client, server := newPeerPair(t)
	defer client.Close()
	defer server.Close()

	want := []byte("hello from client")
	if err := client.Send(want); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := <-server.Incoming()
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestPeerBidirectional(t *testing.T) {
	client, server := newPeerPair(t)
	defer client.Close()
	defer server.Close()

	// client -> server
	if err := client.Send([]byte("from client")); err != nil {
		t.Fatalf("client Send: %v", err)
	}
	if got := <-server.Incoming(); !bytes.Equal(got, []byte("from client")) {
		t.Fatalf("server got %q", got)
	}

	// server -> client
	if err := server.Send([]byte("from server")); err != nil {
		t.Fatalf("server Send: %v", err)
	}
	if got := <-client.Incoming(); !bytes.Equal(got, []byte("from server")) {
		t.Fatalf("client got %q", got)
	}
}

func TestPeerMultipleMessages(t *testing.T) {
	client, server := newPeerPair(t)
	defer client.Close()
	defer server.Close()

	const n = 100
	for i := range n {
		msg := []byte(fmt.Sprintf("message %d", i))
		if err := client.Send(msg); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	for i := range n {
		want := []byte(fmt.Sprintf("message %d", i))
		got := <-server.Incoming()
		if !bytes.Equal(got, want) {
			t.Fatalf("message %d: got %q want %q", i, got, want)
		}
	}
}

func TestPeerCloseSignal(t *testing.T) {
	client, server := newPeerPair(t)
	defer client.Close()

	// closing the server should cause the client's Incoming to close
	server.Close()

	select {
	case _, ok := <-client.Incoming():
		if ok {
			t.Fatal("expected Incoming to be closed after remote disconnect")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for Incoming to close after peer disconnect")
	}
}
