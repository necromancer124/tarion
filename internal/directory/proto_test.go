package directory

import "testing"

func TestValidUsername(t *testing.T) {
	good := []string{"alice", "Bob_2", "a.b-c", "שלום", "x"}
	bad := []string{"", "_alice", ".a", "a b", "a|b", "a:b", "a,b", "a=b", "zzz\nbob", "a\x1b", "abcdefghijklmnopqrstuvwxyz0123456789"}
	for _, n := range good {
		if !ValidUsername(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range bad {
		if ValidUsername(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
	if NameKey("Bob") != NameKey("bob") {
		t.Error("names must be case-insensitive")
	}
}
