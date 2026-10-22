package storage

import (
	"fmt"
	"testing"
	"time"
)

func TestDroppedLogRoundTripAndTrim(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	if got, err := ReadDropped(10); err != nil || len(got) != 0 {
		t.Fatalf("empty log: %v %v", got, err)
	}
	old := droppedTrimBytes
	droppedTrimBytes = 4 * 1024
	defer func() { droppedTrimBytes = old }()

	for i := 0; i < 200; i++ {
		if err := LogDropped(DroppedMessage{Time: time.Now(), Dir: "out", Peer: "bob", Reason: fmt.Sprintf("reason %d", i), Body: "hello"}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := ReadDropped(0)
	if err != nil || len(all) == 0 || len(all) >= 200 {
		t.Fatalf("log should have been trimmed: %d entries, %v", len(all), err)
	}
	last, _ := ReadDropped(1)
	if len(last) != 1 || last[0].Reason != "reason 199" {
		t.Fatalf("newest entry: %+v", last)
	}
}
