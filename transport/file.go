package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const ChunkSize = 64 << 10 // 64 KiB

// SendFile splits path into ChunkSize chunks, sends FILE_META then all
// FILE_CHUNK messages then FILE_DONE with a SHA-256 of the whole file
func SendFile(p *Peer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	size := uint64(info.Size())
	var totalChunks uint32
	if size > 0 {
		totalChunks = uint32((size + ChunkSize - 1) / ChunkSize)
	}

	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}

	if err := p.Send(EncodeFileMeta(FileMeta{
		ID:          id,
		TotalChunks: totalChunks,
		Name:        filepath.Base(path),
		Size:        size,
	})); err != nil {
		return err
	}

	// hash the file as we read it so we dont need a second pass
	h := sha256.New()
	buf := make([]byte, ChunkSize)
	var index uint32
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			h.Write(data)
			if err := p.Send(EncodeFileChunk(FileChunk{
				ID:    id,
				Index: index,
				Data:  data,
			})); err != nil {
				return err
			}
			index++
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return p.Send(EncodeFileDone(id, hash))
}

// FileReceiver accumulates FILE_META / FILE_CHUNK / FILE_DONE messages and
// writes the reassembled file to outputDir once all chunks arrive
type FileReceiver struct {
	outputDir string
	transfers map[[8]byte]*incomingTransfer
}

type incomingTransfer struct {
	meta   FileMeta
	chunks map[uint32][]byte
}

func NewFileReceiver(outputDir string) *FileReceiver {
	return &FileReceiver{
		outputDir: outputDir,
		transfers: make(map[[8]byte]*incomingTransfer),
	}
}

// HandleMessage processes one raw message from Peer.Incoming()
// returns (true, outPath, nil) when a complete file has been written and verified
// returns (false, "", nil) for in-progress messages
func (r *FileReceiver) HandleMessage(data []byte) (done bool, outPath string, err error) {
	typ, payload, err := DecodeMessage(data)
	if err != nil {
		return false, "", err
	}

	switch typ {
	case MsgFileMeta:
		meta, err := DecodeFileMeta(payload)
		if err != nil {
			return false, "", err
		}
		r.transfers[meta.ID] = &incomingTransfer{
			meta:   meta,
			chunks: make(map[uint32][]byte),
		}

	case MsgFileChunk:
		chunk, err := DecodeFileChunk(payload)
		if err != nil {
			return false, "", err
		}
		tf := r.transfers[chunk.ID]
		if tf == nil {
			return false, "", fmt.Errorf("transport: FILE_CHUNK for unknown file id")
		}
		tf.chunks[chunk.Index] = chunk.Data

	case MsgFileDone:
		id, wantHash, err := DecodeFileDone(payload)
		if err != nil {
			return false, "", err
		}
		tf := r.transfers[id]
		if tf == nil {
			return false, "", fmt.Errorf("transport: FILE_DONE for unknown file id")
		}
		outPath, err = r.reassemble(tf, wantHash)
		if err != nil {
			return false, "", err
		}
		delete(r.transfers, id)
		return true, outPath, nil
	}

	return false, "", nil
}

func (r *FileReceiver) reassemble(tf *incomingTransfer, wantHash [32]byte) (string, error) {
	if uint32(len(tf.chunks)) != tf.meta.TotalChunks {
		return "", fmt.Errorf("transport: got %d chunks, want %d", len(tf.chunks), tf.meta.TotalChunks)
	}

	var assembled []byte
	for i := uint32(0); i < tf.meta.TotalChunks; i++ {
		chunk, ok := tf.chunks[i]
		if !ok {
			return "", fmt.Errorf("transport: missing chunk %d", i)
		}
		assembled = append(assembled, chunk...)
	}

	if gotHash := sha256.Sum256(assembled); gotHash != wantHash {
		return "", fmt.Errorf("transport: SHA-256 mismatch, file corrupted in transit")
	}

	// filepath.Base strips any path components from the sender to prevent traversal
	outPath := filepath.Join(r.outputDir, filepath.Base(tf.meta.Name))
	if err := os.WriteFile(outPath, assembled, 0644); err != nil {
		return "", err
	}
	return outPath, nil
}
