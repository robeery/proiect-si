package integration

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"proiect-si/transport"
	"testing"
)

// recvFile drives server.Incoming() through a FileReceiver until one file is
// fully reassembled, then returns the path of the written output file
func recvFile(t *testing.T, server *transport.Peer, outDir string) string {
	t.Helper()
	recvr := transport.NewFileReceiver(outDir)
	for {
		data, ok := <-server.Incoming()
		if !ok {
			t.Fatal("connection closed before file transfer completed")
		}
		done, outPath, err := recvr.HandleMessage(data)
		if err != nil {
			t.Fatalf("HandleMessage: %v", err)
		}
		if done {
			return outPath
		}
	}
}

// TestPeerFileTransferLarge sends a 2 MB file over an encrypted TCP connection
// and verifies the received file matches the original byte for byte
// this is the week 10 milestone: split into chunks, encrypt, send, reassemble, verify
func TestPeerFileTransferLarge(t *testing.T) {
	original := make([]byte, 2<<20) // 2 MiB = 32 chunks of 64 KiB
	if _, err := rand.Read(original); err != nil {
		t.Fatalf("rand: %v", err)
	}

	srcDir := t.TempDir()
	srcFile := srcDir + "/payload.bin"
	if err := os.WriteFile(srcFile, original, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	client, server := dialAndAccept(t)
	defer client.Close()
	defer server.Close()

	sendErr := make(chan error, 1)
	go func() { sendErr <- transport.SendFile(client, srcFile) }()

	outPath := recvFile(t, server, t.TempDir())

	if err := <-sendErr; err != nil {
		t.Fatalf("SendFile: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if !bytes.Equal(got, original) {
		t.Fatalf("content mismatch: got %d bytes want %d", len(got), len(original))
	}

	// also verify SHA-256 explicitly so the test documents the integrity guarantee
	wantHash := sha256.Sum256(original)
	gotHash := sha256.Sum256(got)
	if gotHash != wantHash {
		t.Fatalf("SHA-256 mismatch:\n got  %x\n want %x", gotHash, wantHash)
	}
}

// TestPeerFilesSequential sends two different files on the same encrypted connection
// verifies the session and FileReceiver state hold up across multiple transfers
func TestPeerFilesSequential(t *testing.T) {
	client, server := dialAndAccept(t)
	defer client.Close()
	defer server.Close()

	files := []struct {
		name string
		data []byte
	}{
		{"first.bin", make([]byte, 100*1024)},  // 100 KiB, less than 2 chunks
		{"second.bin", make([]byte, 130*1024)}, // 130 KiB, 3 chunks
	}
	for i := range files {
		if _, err := rand.Read(files[i].data); err != nil {
			t.Fatalf("rand: %v", err)
		}
	}

	outDir := t.TempDir()
	recvr := transport.NewFileReceiver(outDir)

	for _, f := range files {
		srcFile := t.TempDir() + "/" + f.name
		if err := os.WriteFile(srcFile, f.data, 0644); err != nil {
			t.Fatalf("WriteFile %s: %v", f.name, err)
		}

		sendErr := make(chan error, 1)
		go func() { sendErr <- transport.SendFile(client, srcFile) }()

		// drain until this file is done
		for {
			data, ok := <-server.Incoming()
			if !ok {
				t.Fatalf("connection closed during transfer of %s", f.name)
			}
			done, outPath, err := recvr.HandleMessage(data)
			if err != nil {
				t.Fatalf("HandleMessage (%s): %v", f.name, err)
			}
			if done {
				if err := <-sendErr; err != nil {
					t.Fatalf("SendFile %s: %v", f.name, err)
				}
				got, err := os.ReadFile(outPath)
				if err != nil {
					t.Fatalf("ReadFile %s: %v", f.name, err)
				}
				if !bytes.Equal(got, f.data) {
					t.Fatalf("%s: content mismatch: got %d bytes want %d", f.name, len(got), len(f.data))
				}
				break
			}
		}
	}
}
