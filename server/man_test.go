package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestManPageUpToDate fails when a flag changed without regenerating the
// man page: go run ./server man > docs/man/tariond.8
func TestManPageUpToDate(t *testing.T) {
	t.Setenv("TARIOND_DATA", "") // the -data default comes from it
	var buf bytes.Buffer
	writeManPage(&buf)
	want, err := os.ReadFile("../docs/man/tariond.8")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(want), "\r\n", "\n") != buf.String() {
		t.Fatal("docs/man/tariond.8 is out of date; regenerate it with: go run ./server man > docs/man/tariond.8")
	}
}
