package transport

import (
	"encoding/binary"
	"errors"
)

type MsgType byte

const (
	MsgText      MsgType = 0x01
	MsgFileMeta  MsgType = 0x02
	MsgFileChunk MsgType = 0x03
	MsgFileDone  MsgType = 0x04
)

// FileMeta is sent once before the chunks to tell the receiver what to expect
type FileMeta struct {
	ID          [8]byte
	TotalChunks uint32
	Name        string
	Size        uint64
}

// FileChunk carries one piece of a file identified by ID and its position
type FileChunk struct {
	ID    [8]byte
	Index uint32
	Data  []byte
}

var ErrEmptyMessage = errors.New("transport: empty message, no type byte")

// DecodeMessage splits the type byte from the rest of the payload
// caller uses the returned type to pick the right Decode* helper
func DecodeMessage(data []byte) (MsgType, []byte, error) {
	if len(data) == 0 {
		return 0, nil, ErrEmptyMessage
	}
	return MsgType(data[0]), data[1:], nil
}

func EncodeText(text string) []byte {
	out := make([]byte, 1+len(text))
	out[0] = byte(MsgText)
	copy(out[1:], text)
	return out
}

func DecodeText(payload []byte) string {
	return string(payload)
}

// EncodeFileMeta layout: file_id(8) | total_chunks(4) | name_len(2) | name | size(8)
func EncodeFileMeta(m FileMeta) []byte {
	name := []byte(m.Name)
	out := make([]byte, 1+8+4+2+len(name)+8)
	i := 0
	out[i] = byte(MsgFileMeta)
	i++
	copy(out[i:], m.ID[:])
	i += 8
	binary.BigEndian.PutUint32(out[i:], m.TotalChunks)
	i += 4
	binary.BigEndian.PutUint16(out[i:], uint16(len(name)))
	i += 2
	copy(out[i:], name)
	i += len(name)
	binary.BigEndian.PutUint64(out[i:], m.Size)
	return out
}

func DecodeFileMeta(payload []byte) (FileMeta, error) {
	if len(payload) < 8+4+2 {
		return FileMeta{}, errors.New("transport: FILE_META payload too short")
	}
	var m FileMeta
	i := 0
	copy(m.ID[:], payload[i:])
	i += 8
	m.TotalChunks = binary.BigEndian.Uint32(payload[i:])
	i += 4
	nameLen := int(binary.BigEndian.Uint16(payload[i:]))
	i += 2
	if len(payload[i:]) < nameLen+8 {
		return FileMeta{}, errors.New("transport: FILE_META truncated name or size field")
	}
	m.Name = string(payload[i : i+nameLen])
	i += nameLen
	m.Size = binary.BigEndian.Uint64(payload[i:])
	return m, nil
}

// EncodeFileChunk layout: file_id(8) | chunk_index(4) | data
func EncodeFileChunk(c FileChunk) []byte {
	out := make([]byte, 1+8+4+len(c.Data))
	i := 0
	out[i] = byte(MsgFileChunk)
	i++
	copy(out[i:], c.ID[:])
	i += 8
	binary.BigEndian.PutUint32(out[i:], c.Index)
	i += 4
	copy(out[i:], c.Data)
	return out
}

func DecodeFileChunk(payload []byte) (FileChunk, error) {
	if len(payload) < 8+4 {
		return FileChunk{}, errors.New("transport: FILE_CHUNK payload too short")
	}
	var c FileChunk
	copy(c.ID[:], payload[:8])
	c.Index = binary.BigEndian.Uint32(payload[8:])
	c.Data = payload[12:]
	return c, nil
}

// EncodeFileDone layout: file_id(8) | sha256(32)
func EncodeFileDone(id [8]byte, hash [32]byte) []byte {
	out := make([]byte, 1+8+32)
	out[0] = byte(MsgFileDone)
	copy(out[1:], id[:])
	copy(out[9:], hash[:])
	return out
}

func DecodeFileDone(payload []byte) (id [8]byte, hash [32]byte, err error) {
	if len(payload) < 8+32 {
		err = errors.New("transport: FILE_DONE payload too short")
		return
	}
	copy(id[:], payload[:8])
	copy(hash[:], payload[8:40])
	return
}
