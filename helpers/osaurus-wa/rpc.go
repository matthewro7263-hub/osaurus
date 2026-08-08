// JSON-RPC 2.0 server over stdio, newline-framed (one JSON object per line),
// matching the protocol shape of the pinned `imsg rpc` helper: responses
// carry the request `id`; helper-initiated notifications carry a `method`
// and `params` but no `id`.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int            `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// stdioWriter serializes all stdout writes so responses and asynchronous
// notifications never interleave mid-line.
type stdioWriter struct {
	mu  sync.Mutex
	out *bufio.Writer
}

func newStdioWriter() *stdioWriter {
	return &stdioWriter{out: bufio.NewWriter(os.Stdout)}
}

func (w *stdioWriter) writeLine(payload map[string]any) {
	line, err := json.Marshal(payload)
	if err != nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.out.Write(line)
	w.out.WriteByte('\n')
	w.out.Flush()
}

func (w *stdioWriter) respond(id int, result map[string]any) {
	if result == nil {
		result = map[string]any{}
	}
	w.writeLine(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func (w *stdioWriter) respondError(id int, code int, message string) {
	w.writeLine(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   rpcError{Code: code, Message: message},
	})
}

// notify emits a helper-initiated notification (no id).
func (w *stdioWriter) notify(method string, params map[string]any) {
	if params == nil {
		params = map[string]any{}
	}
	w.writeLine(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

func runRPC(storeDir string) {
	writer := newStdioWriter()
	bridge, err := newBridge(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "osaurus-wa: cannot open session store: %v\n", err)
		os.Exit(1)
	}
	bridge.writer = writer
	defer bridge.close()

	reader := bufio.NewReaderSize(os.Stdin, 64*1024)
	// A single oversized frame must not take the helper down with it: an
	// unreadable line is skipped and the loop keeps serving, because exiting
	// here would silently drop every active watch.subscribe.
	for {
		line, err := readFrame(reader)
		if len(line) > 0 {
			var request rpcRequest
			if err := json.Unmarshal(line, &request); err == nil && request.Method != "" &&
				request.ID != nil { // the Swift side never sends notifications
				id := *request.ID
				result, rpcErr := bridge.handle(request.Method, request.Params)
				if rpcErr != nil {
					writer.respondError(id, rpcErr.Code, rpcErr.Message)
				} else {
					writer.respond(id, result)
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return // stdin closed: the Swift side is done with us
			}
			if errors.Is(err, errFrameTooLong) {
				// The frame was consumed up to its newline, so the next
				// iteration resynchronizes on the following request.
				fmt.Fprintf(os.Stderr, "osaurus-wa: dropping oversized request frame\n")
				continue
			}
			fmt.Fprintf(os.Stderr, "osaurus-wa: stdin read failed: %v\n", err)
			return
		}
	}
}

// maxFrameBytes bounds a single JSON-RPC line. Requests are small, but the
// limit stays generous for forward compatibility.
const maxFrameBytes = 4 * 1024 * 1024

// errFrameTooLong reports a line that exceeded maxFrameBytes. The frame has
// still been drained through its newline, so the caller can resynchronize.
var errFrameTooLong = errors.New("request frame exceeds size limit")

// readFrame reads one newline-delimited frame. It returns the frame without
// its newline, plus an error describing why reading stopped. An oversized
// frame is discarded (not buffered) and reported as errFrameTooLong after the
// rest of the line has been drained, so the stream stays aligned.
func readFrame(reader *bufio.Reader) ([]byte, error) {
	var frame []byte
	oversized := false
	for {
		chunk, err := reader.ReadSlice('\n')
		if !oversized {
			if len(frame)+len(chunk) > maxFrameBytes {
				oversized = true
				frame = nil
			} else {
				frame = append(frame, chunk...)
			}
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue // more of this line is pending
		}
		// io.EOF (or a real read error) with a trailing partial line: hand
		// back whatever arrived so a final unterminated frame still runs.
		if oversized {
			return nil, errFrameTooLong
		}
		return dropCR(frame), err
	}
	if oversized {
		return nil, errFrameTooLong
	}
	return dropCR(frame[:len(frame)-1]), nil
}

// dropCR strips a trailing carriage return, matching how bufio.ScanLines
// (which this reader replaced) normalized CRLF-terminated frames.
func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[:len(data)-1]
	}
	return data
}
