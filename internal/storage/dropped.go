package storage

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DroppedMessage records a message that will never be delivered: one you
// sent that was given up on, or one you received and refused.
type DroppedMessage struct {
	Time   time.Time `json:"time"`
	Dir    string    `json:"dir"`  // "out" (you sent it) or "in" (you refused it)
	Peer   string    `json:"peer"` // contact name, or peer-<id> if unknown
	Reason string    `json:"reason"`
	Body   string    `json:"body,omitempty"` // outgoing only: what was lost
}

var (
	droppedMu sync.Mutex
	// droppedTrimBytes caps dropped.log; past it the oldest half is cut.
	droppedTrimBytes int64 = 512 * 1024
)

func GetDroppedPath() string { return filepath.Join(GetBaseConfigDir(), "dropped.log") }

// LogDropped appends one entry (a JSON object per line).
func LogDropped(d DroppedMessage) error {
	droppedMu.Lock()
	defer droppedMu.Unlock()
	path := GetDroppedPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	line, err := json.Marshal(d)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	_ = f.Close()
	if err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil && info.Size() > droppedTrimBytes {
		lines, err := readLines(path)
		if err == nil {
			lines = lines[len(lines)/2:]
			return writeFileAtomic(path, []byte(strings.Join(lines, "\n")+"\n"))
		}
	}
	return nil
}

// ReadDropped returns up to n of the most recent entries, oldest first
// (all of them when n <= 0).
func ReadDropped(n int) ([]DroppedMessage, error) {
	droppedMu.Lock()
	lines, err := readLines(GetDroppedPath())
	droppedMu.Unlock()
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []DroppedMessage
	for _, l := range lines {
		var d DroppedMessage
		if json.Unmarshal([]byte(l), &d) == nil {
			out = append(out, d)
		}
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if l := strings.TrimSpace(scanner.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, scanner.Err()
}
