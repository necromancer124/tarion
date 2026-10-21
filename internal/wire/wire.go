// Package wire is Tarion's framing: every message on a QUIC stream is a
// 4-byte big-endian length followed by that many bytes of JSON.
package wire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxFrameSize caps a single frame so a peer cannot make us allocate much.
const MaxFrameSize = 64 * 1024

// WriteFrame encodes v as JSON and writes it as one frame.
func WriteFrame(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > MaxFrameSize {
		return errors.New("frame too large")
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf, uint32(len(data)))
	copy(buf[4:], data)
	_, err = w.Write(buf)
	return err
}

// ReadFrame reads one frame and decodes its JSON into v.
func ReadFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("read frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrameSize {
		return fmt.Errorf("frame size %d out of range", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return fmt.Errorf("read frame: %w", err)
	}
	return json.Unmarshal(data, v)
}
