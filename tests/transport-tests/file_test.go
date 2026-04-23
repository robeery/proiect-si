package transporttests

import (
	"bytes"
	"crypto/rand"
	"os"
	"proiect-si/transport"
	"testing"
)

// sendAndReceiveFile sends path over a Peer pair and returns the path of the
// reassembled output file written into outDir
func sendAndReceiveFile(t *testing.T, path, outDir string) string {
	t.Helper()
	client, server := newPeerPair(t)
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- transport.SendFile(client, path) }()

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
			if sendErr := <-errCh; sendErr != nil {
				t.Fatalf("SendFile: %v", sendErr)
			}
			return outPath
		}
	}
}

func TestFileTransferSmall(t *testing.T) {
	// smaller than one chunk
	original := make([]byte, 3*1024)
	if _, err := rand.Read(original); err != nil {
		t.Fatalf("rand: %v", err)
	}

	srcFile := t.TempDir() + "/small.bin"
	if err := os.WriteFile(srcFile, original, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	outPath := sendAndReceiveFile(t, srcFile, t.TempDir())

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("content mismatch: got %d bytes want %d", len(got), len(original))
	}
}

func TestFileTransferMultiChunk(t *testing.T) {
	// spans 3 chunks
	original := make([]byte, 3*transport.ChunkSize-7)
	if _, err := rand.Read(original); err != nil {
		t.Fatalf("rand: %v", err)
	}

	srcFile := t.TempDir() + "/multi.bin"
	if err := os.WriteFile(srcFile, original, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	outPath := sendAndReceiveFile(t, srcFile, t.TempDir())

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("content mismatch: got %d bytes want %d", len(got), len(original))
	}
}

func TestFileTransferEmpty(t *testing.T) {
	srcFile := t.TempDir() + "/empty.bin"
	if err := os.WriteFile(srcFile, []byte{}, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	outPath := sendAndReceiveFile(t, srcFile, t.TempDir())

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty file, got %d bytes", len(got))
	}
}

func TestFileReceiverHashMismatch(t *testing.T) {
	recvr := transport.NewFileReceiver(t.TempDir())

	id := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

	// send valid META
	meta := transport.FileMeta{ID: id, TotalChunks: 1, Name: "test.bin", Size: 4}
	if _, _, err := recvr.HandleMessage(transport.EncodeFileMeta(meta)); err != nil {
		t.Fatalf("meta: %v", err)
	}

	// send the chunk
	if _, _, err := recvr.HandleMessage(transport.EncodeFileChunk(transport.FileChunk{
		ID:    id,
		Index: 0,
		Data:  []byte("data"),
	})); err != nil {
		t.Fatalf("chunk: %v", err)
	}

	// send DONE with a wrong hash
	var badHash [32]byte
	_, _, err := recvr.HandleMessage(transport.EncodeFileDone(id, badHash))
	if err == nil {
		t.Fatal("expected SHA-256 mismatch error, got nil")
	}
}
