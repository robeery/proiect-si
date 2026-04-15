package transporttests

import (
	"bytes"
	"errors"
	"io"
	"proiect-si/transport"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
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
			var buf bytes.Buffer
			if err := transport.WriteFrame(&buf, tc.payload); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			got, err := transport.ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if !bytes.Equal(got, tc.payload) {
				t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(tc.payload))
			}
		})
	}
}

func TestFrameMultipleSequential(t *testing.T) {
	payloads := [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte(""),
		bytes.Repeat([]byte{0x01}, 100),
		[]byte("last"),
	}
	var buf bytes.Buffer
	for _, p := range payloads {
		if err := transport.WriteFrame(&buf, p); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}
	for i, want := range payloads {
		got, err := transport.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d mismatch: got %x want %x", i, got, want)
		}
	}
}

func TestFrameExactlyAtLimit(t *testing.T) {
	payload := make([]byte, transport.MaxFrameSize)
	var buf bytes.Buffer
	if err := transport.WriteFrame(&buf, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := transport.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(got) != transport.MaxFrameSize {
		t.Fatalf("got %d bytes, want %d", len(got), transport.MaxFrameSize)
	}
}

func TestFrameOversizeWrite(t *testing.T) {
	huge := make([]byte, transport.MaxFrameSize+1)
	var buf bytes.Buffer
	err := transport.WriteFrame(&buf, huge)
	if !errors.Is(err, transport.ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("nothing should have been written, got %d bytes", buf.Len())
	}
}

// Hand-craft a header claiming a body larger than MaxFrameSize and confirm
// the reader rejects it without attempting to allocate.
func TestFrameOversizeRead(t *testing.T) {
	buf := bytes.NewReader([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	_, err := transport.ReadFrame(buf)
	if !errors.Is(err, transport.ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestFrameTruncatedHeader(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x00, 0x00})
	_, err := transport.ReadFrame(buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF/ErrUnexpectedEOF, got %v", err)
	}
}

func TestFrameTruncatedBody(t *testing.T) {
	body := []byte{0x00, 0x00, 0x00, 0x64} // header claims 100 bytes
	body = append(body, []byte("short")...) // only 5 follow
	buf := bytes.NewReader(body)
	_, err := transport.ReadFrame(buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestFramePipe(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()

	payload := []byte("over a pipe")
	errCh := make(chan error, 1)
	go func() { errCh <- transport.WriteFrame(w, payload) }()

	got, err := transport.ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("WriteFrame: %v", writeErr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %x want %x", got, payload)
	}
}
