package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := map[string]string{"op": "login", "user": "שלום"}
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := ReadFrame(&buf, &out); err != nil {
		t.Fatal(err)
	}
	if out["user"] != "שלום" || out["op"] != "login" {
		t.Fatalf("round trip: %v", out)
	}
}

func TestReadFrameRejectsHugeLength(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(MaxFrameSize+1))
	var v any
	if err := ReadFrame(&buf, &v); err == nil {
		t.Fatal("expected oversized frame header to be rejected")
	}
}

func TestReadFrameRejectsEmpty(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))
	var v any
	if err := ReadFrame(&buf, &v); err == nil {
		t.Fatal("expected empty frame to be rejected")
	}
}
