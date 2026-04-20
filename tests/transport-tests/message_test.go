package transporttests

import (
	"bytes"
	"errors"
	"proiect-si/transport"
	"testing"
)

func TestEncodeDecodeText(t *testing.T) {
	cases := []string{"", "hello", "unicode: ăîșțâ", "long: " + string(bytes.Repeat([]byte("x"), 1000))}
	for _, tc := range cases {
		raw := transport.EncodeText(tc)
		typ, payload, err := transport.DecodeMessage(raw)
		if err != nil {
			t.Fatalf("DecodeMessage: %v", err)
		}
		if typ != transport.MsgText {
			t.Fatalf("wrong type: got %v want MsgText", typ)
		}
		if got := transport.DecodeText(payload); got != tc {
			t.Fatalf("text mismatch: got %q want %q", got, tc)
		}
	}
}

func TestEncodeDecodeFileMeta(t *testing.T) {
	cases := []transport.FileMeta{
		{ID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, TotalChunks: 42, Name: "photo.jpg", Size: 1234567},
		{ID: [8]byte{}, TotalChunks: 1, Name: "", Size: 0},
		{ID: [8]byte{0xFF}, TotalChunks: 100000, Name: "long-filename-with-unicode-ăîșț.bin", Size: 1 << 30},
	}
	for _, want := range cases {
		raw := transport.EncodeFileMeta(want)
		typ, payload, err := transport.DecodeMessage(raw)
		if err != nil {
			t.Fatalf("DecodeMessage: %v", err)
		}
		if typ != transport.MsgFileMeta {
			t.Fatalf("wrong type: got %v", typ)
		}
		got, err := transport.DecodeFileMeta(payload)
		if err != nil {
			t.Fatalf("DecodeFileMeta: %v", err)
		}
		if got.ID != want.ID || got.TotalChunks != want.TotalChunks ||
			got.Name != want.Name || got.Size != want.Size {
			t.Fatalf("FileMeta mismatch:\n got  %+v\n want %+v", got, want)
		}
	}
}

func TestEncodeDecodeFileChunk(t *testing.T) {
	cases := []transport.FileChunk{
		{ID: [8]byte{1}, Index: 0, Data: []byte("chunk zero data")},
		{ID: [8]byte{2}, Index: 999, Data: bytes.Repeat([]byte{0xAB}, 65536)},
		{ID: [8]byte{3}, Index: 0, Data: []byte{}},
	}
	for _, want := range cases {
		raw := transport.EncodeFileChunk(want)
		typ, payload, err := transport.DecodeMessage(raw)
		if err != nil {
			t.Fatalf("DecodeMessage: %v", err)
		}
		if typ != transport.MsgFileChunk {
			t.Fatalf("wrong type: got %v", typ)
		}
		got, err := transport.DecodeFileChunk(payload)
		if err != nil {
			t.Fatalf("DecodeFileChunk: %v", err)
		}
		if got.ID != want.ID || got.Index != want.Index || !bytes.Equal(got.Data, want.Data) {
			t.Fatalf("FileChunk mismatch: index %d", want.Index)
		}
	}
}

func TestEncodeDecodeFileDone(t *testing.T) {
	wantID := [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33}
	wantHash := [32]byte{0: 0xAA, 31: 0xBB}

	raw := transport.EncodeFileDone(wantID, wantHash)
	typ, payload, err := transport.DecodeMessage(raw)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if typ != transport.MsgFileDone {
		t.Fatalf("wrong type: got %v", typ)
	}
	gotID, gotHash, err := transport.DecodeFileDone(payload)
	if err != nil {
		t.Fatalf("DecodeFileDone: %v", err)
	}
	if gotID != wantID || gotHash != wantHash {
		t.Fatalf("FileDone mismatch: id %x hash %x", gotID, gotHash)
	}
}

func TestDecodeMessageEmpty(t *testing.T) {
	_, _, err := transport.DecodeMessage([]byte{})
	if !errors.Is(err, transport.ErrEmptyMessage) {
		t.Fatalf("expected ErrEmptyMessage, got %v", err)
	}
}

func TestDecodeFileMetaTruncated(t *testing.T) {
	if _, err := transport.DecodeFileMeta([]byte{0x01, 0x02}); err == nil {
		t.Fatal("expected error for truncated FILE_META payload")
	}
}

func TestDecodeFileChunkTruncated(t *testing.T) {
	if _, err := transport.DecodeFileChunk([]byte{0x01, 0x02}); err == nil {
		t.Fatal("expected error for truncated FILE_CHUNK payload")
	}
}

func TestDecodeFileDoneTruncated(t *testing.T) {
	if _, _, err := transport.DecodeFileDone([]byte{0x01, 0x02}); err == nil {
		t.Fatal("expected error for truncated FILE_DONE payload")
	}
}
