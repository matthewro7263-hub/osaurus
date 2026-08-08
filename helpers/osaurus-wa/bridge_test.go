package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// After a logout or remote unlink, whatsmeow marks the device Deleted and
// swaps its stores for failing stubs, so Connect refuses with
// ErrDeviceDeleted and the phone could never re-pair through the same
// long-lived helper process. resetClientForPairing must hand the bridge a
// fresh, usable device + client.
func TestResetClientForPairingReplacesDeletedDevice(t *testing.T) {
	b, err := newBridge(t.TempDir())
	if err != nil {
		t.Fatalf("newBridge: %v", err)
	}
	defer b.close()

	// Simulate what whatsmeow's Device.Delete does on unlink (the real call
	// needs a linked JID, which a unit test doesn't have).
	b.client.Store.Deleted = true

	old := b.client
	b.resetClientForPairing()
	if b.client == old {
		t.Fatal("expected a new client after reset")
	}
	if b.client.Store.Deleted {
		t.Fatal("expected the replacement device to be usable")
	}
	if b.client.Store.ID != nil {
		t.Fatal("expected the replacement device to be unlinked")
	}
}

// The passkey response RPC must reject malformed input up front (-32602)
// before anything reaches the wire: missing param, non-JSON payload, and
// assertions missing required WebAuthn fields.
func TestHandlePasskeyResponseValidation(t *testing.T) {
	b := &bridge{}
	cases := map[string]string{
		"missing params":       ``,
		"missing response":     `{}`,
		"payload not json":     `{"response_json":"not json"}`,
		"incomplete assertion": `{"response_json":"{\"id\":\"\",\"rawId\":\"\",\"response\":{}}"}`,
	}
	for name, params := range cases {
		var raw json.RawMessage
		if params != "" {
			raw = json.RawMessage(params)
		}
		result, rpcErr := b.handlePasskeyResponse(raw)
		if result != nil || rpcErr == nil || rpcErr.Code != -32602 {
			t.Errorf("%s: expected -32602 refusal, got result=%v err=%+v", name, result, rpcErr)
		}
	}
}

// Helper-written media paths must never traverse or hide: no separators,
// no leading dots, bounded length.
func TestSanitizeFileName(t *testing.T) {
	cases := map[string]string{
		"photo.jpg": "photo.jpg",
		// Separators are replaced and leading dots stripped, so the result
		// can never traverse out of the media directory.
		"../../etc/passwd":   "_.._etc_passwd",
		".hidden":            "hidden",
		"weird name (1).png": "weird_name__1_.png",
		"a/b\\c:d.pdf":       "a_b_c_d.pdf",
	}
	for input, want := range cases {
		if got := sanitizeFileName(input); got != want {
			t.Errorf("sanitizeFileName(%q) = %q, want %q", input, got, want)
		}
	}

	long := strings.Repeat("x", 200) + ".jpg"
	sanitized := sanitizeFileName(long)
	if len(sanitized) != 120 {
		t.Errorf("long name should truncate to 120 chars, got %d", len(sanitized))
	}
	if !strings.HasSuffix(sanitized, ".jpg") {
		t.Errorf("truncation must keep the tail (extension), got %q", sanitized)
	}
}

// An omitted or zero max_media_bytes must not disable the cap, and a value
// above the hard ceiling must not raise it — only a stricter cap wins.
func TestEffectiveMediaLimit(t *testing.T) {
	cases := []struct {
		configured int64
		want       int64
	}{
		{0, defaultMaxInboundMediaBytes},
		{-1, defaultMaxInboundMediaBytes},
		{defaultMaxInboundMediaBytes + 1, defaultMaxInboundMediaBytes},
		{1024, 1024},
		{defaultMaxInboundMediaBytes, defaultMaxInboundMediaBytes},
	}
	for _, c := range cases {
		if got := effectiveMediaLimit(c.configured); got != c.want {
			t.Errorf("effectiveMediaLimit(%d) = %d, want %d", c.configured, got, c.want)
		}
	}
}

// The sender-declared FileLength is untrusted, so the cap has to bite on the
// bytes actually written. cappedFile must refuse the write that would cross
// the limit and leave the file no larger than the limit.
func TestCappedFileStopsAtLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "media.bin")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer file.Close()

	capped := &cappedFile{File: file, limit: 100}
	// Mirror production exactly: whatsmeow holds the destination as a plain
	// io.Writer and copies from an io.TeeReader. A TeeReader is not an
	// io.WriterTo, so io.Copy must fall through to `dst.(io.ReaderFrom)` —
	// the branch that silently bypassed the cap before ReadFrom was shadowed.
	// (Copying from a *bytes.Reader instead would take the src.WriteTo branch
	// and exercise Write directly, which is why the earlier version of this
	// test passed against a cap that did nothing in production.)
	var sink io.Writer = capped
	src := io.TeeReader(bytes.NewReader(make([]byte, 1024*1024)), io.Discard)
	// A sender that declared "1 byte" but ships 1 MiB is stopped mid-stream.
	n, err := io.Copy(sink, src)
	if !errors.Is(err, errMediaTooLarge) {
		t.Fatalf("expected errMediaTooLarge, got %v", err)
	}
	if !capped.exceeded {
		t.Error("expected the exceeded flag to be set")
	}
	if n > 100 {
		t.Errorf("wrote %d bytes past the 100-byte limit", n)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() > 100 {
		t.Errorf("file grew to %d bytes past the 100-byte limit", info.Size())
	}
}

// Writes at or below the limit must pass through untouched, and a rewind
// (whatsmeow retries a failed download by seeking back to 0) must rewind the
// cap accounting too, or a legitimate retry would spuriously trip it.
func TestCappedFileAllowsLimitAndRewind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "media.bin")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer file.Close()

	capped := &cappedFile{File: file, limit: 64}
	if _, err := capped.Write(make([]byte, 64)); err != nil {
		t.Fatalf("writing exactly the limit must succeed, got %v", err)
	}
	if _, err := capped.Write([]byte{0}); !errors.Is(err, errMediaTooLarge) {
		t.Fatalf("expected errMediaTooLarge past the limit, got %v", err)
	}

	capped.exceeded = false
	if _, err := capped.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}
	if _, err := capped.Write(make([]byte, 64)); err != nil {
		t.Errorf("a full rewrite after rewinding must succeed, got %v", err)
	}
}

// A frame at or under the limit round-trips; an oversized frame is dropped
// with errFrameTooLong and the reader stays aligned on the next frame, so a
// single bad line can never end the RPC loop.
func TestReadFrameResynchronizesAfterOversizedFrame(t *testing.T) {
	huge := strings.Repeat("x", maxFrameBytes+1)
	input := "{\"a\":1}\r\n" + huge + "\n" + "{\"b\":2}\n"
	reader := bufio.NewReaderSize(strings.NewReader(input), 64*1024)

	// CRLF is normalized away, matching the bufio.Scanner this replaced.
	frame, err := readFrame(reader)
	if err != nil || string(frame) != `{"a":1}` {
		t.Fatalf("first frame = %q, %v", frame, err)
	}

	frame, err = readFrame(reader)
	if !errors.Is(err, errFrameTooLong) {
		t.Fatalf("expected errFrameTooLong, got %q, %v", frame, err)
	}
	if len(frame) != 0 {
		t.Errorf("an oversized frame must not be buffered, got %d bytes", len(frame))
	}

	frame, err = readFrame(reader)
	if err != nil || string(frame) != `{"b":2}` {
		t.Fatalf("expected to resynchronize on the next frame, got %q, %v", frame, err)
	}

	if frame, err = readFrame(reader); !errors.Is(err, io.EOF) || len(frame) != 0 {
		t.Fatalf("expected clean EOF, got %q, %v", frame, err)
	}
}

// A final frame with no trailing newline must still be handed back (the old
// bufio.Scanner returned it), alongside the EOF that ends the loop.
func TestReadFrameReturnsUnterminatedTail(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader(`{"a":1}`), 64*1024)
	frame, err := readFrame(reader)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
	if string(frame) != `{"a":1}` {
		t.Errorf("expected the unterminated tail, got %q", frame)
	}
}

func TestExtensionForMime(t *testing.T) {
	cases := []struct {
		mimetype  string
		mediaType string
		want      string
	}{
		{"image/jpeg", "image", ".jpg"},
		{"image/jpeg; codecs=whatever", "image", ".jpg"},
		{"video/mp4", "video", ".mp4"},
		{"audio/ogg", "audio", ".ogg"},
		{"application/pdf", "document", ".pdf"},
		// Unknown MIME falls back by media class.
		{"application/x-unknown-thing", "image", ".jpg"},
	}
	for _, c := range cases {
		if got := extensionForMime(c.mimetype, c.mediaType); got != c.want {
			t.Errorf("extensionForMime(%q, %q) = %q, want %q", c.mimetype, c.mediaType, got, c.want)
		}
	}
}
