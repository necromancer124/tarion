package main

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestManPageUpToDate fails when a command or flag changed without
// regenerating the man page: go run . man > docs/man/tarion.1
func TestManPageUpToDate(t *testing.T) {
	var buf bytes.Buffer
	writeManPage(&buf)
	want, err := os.ReadFile("docs/man/tarion.1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(want), "\r\n", "\n") != buf.String() {
		t.Fatal("docs/man/tarion.1 is out of date; regenerate it with: go run . man > docs/man/tarion.1")
	}
}

func TestTopicsAreConsistent(t *testing.T) {
	topics := loadTopics()
	names := map[string]bool{}
	for _, tp := range topics {
		if tp.name == "" || tp.summary == "" {
			t.Errorf("a topic file must start with \"# name: summary\": %+v", tp.name)
		}
		if _, err := topicFiles.ReadFile("docs/topics/" + tp.name + ".md"); err != nil {
			t.Errorf("topic %q is not in %s.md", tp.name, tp.name)
		}
		names[tp.name] = true
	}
	for _, c := range commands {
		if c.topic != "" && !names[c.topic] {
			t.Errorf("command %s points to missing topic %q", c.name, c.topic)
		}
	}
	seeAlso := regexp.MustCompile(`(?m)^See also: (.+)\.$`)
	for _, tp := range topics {
		m := seeAlso.FindStringSubmatch(tp.body)
		if m == nil {
			t.Errorf("topic %s has no \"See also:\" line", tp.name)
			continue
		}
		for _, ref := range strings.Split(m[1], ", ") {
			if !names[ref] {
				t.Errorf("topic %s refers to missing topic %q", tp.name, ref)
			}
		}
	}
}

func TestHelpText(t *testing.T) {
	out := plainText("## Title\n\nUse **bold** and `code` and [a link](https://x.test) or [a doc](docs/a.md).\n\n```\ncmd one\n```\n\n| A | B |\n|---|---|\n| long cell | b |\n")
	for _, want := range []string{"TITLE", "Use bold and code and a link (https://x.test) or a doc.", "    cmd one", "  long cell  b"} {
		if !strings.Contains(out, want) {
			t.Errorf("plain text lacks %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"**", "```", "|---"} {
		if strings.Contains(out, bad) {
			t.Errorf("plain text still has %q:\n%s", bad, out)
		}
	}
	if err := runHelp([]string{"no-such-topic"}); err == nil {
		t.Fatal("unknown topic accepted")
	}
}
