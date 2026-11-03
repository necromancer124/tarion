package firewall

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

const exe = `C:\Tools\tarion.exe`

func TestDecide(t *testing.T) {
	on := func(rules ...Rule) Report { return Report{Enabled: true, DefaultBlock: true, Rules: rules} }
	for name, c := range map[string]struct {
		r       Report
		blocked bool
		reason  string
	}{
		"firewall off":            {Report{Enabled: false, DefaultBlock: true}, false, ""},
		"inbound allowed":         {Report{Enabled: true}, false, ""},
		"no rule":                 {on(), true, "no rule that allows tarion.exe on UDP port 63426"},
		"rule for us":             {on(Rule{App: `c:\tools\TARION.EXE`, Ports: "63426", Action: 1}), false, ""},
		"rule for us, any port":   {on(Rule{App: exe, Ports: "*", Action: 1}), false, ""},
		"rule for us, other port": {on(Rule{App: exe, Ports: "5000", Action: 1}), true, "no rule"},
		"port rule, any program":  {on(Rule{Ports: "60000-64000", Action: 1}), false, ""},
		"port list":               {on(Rule{Ports: "RPC, 80,63426", Action: 1}), false, ""},
		"cancel click blocks":     {on(Rule{App: exe, Ports: "*", Action: 0}, Rule{App: exe, Ports: "*", Action: 1}), true, "Cancel"},
		"port blocked for all":    {on(Rule{Ports: "63426", Action: 0}, Rule{App: exe, Ports: "*", Action: 1}), true, "every program"},
		"other port blocked":      {on(Rule{Ports: "445", Action: 0}, Rule{App: exe, Ports: "*", Action: 1}), false, ""},
		"LAN only":                {on(Rule{App: exe, Ports: "*", Remote: "LocalSubnet", Action: 1}), true, "no rule"},
		"any remote spelled out":  {on(Rule{App: exe, Ports: "*", Remote: "*", Action: 1}), false, ""},
	} {
		s := Decide(c.r, exe, 63426)
		if !s.Known || s.Blocked != c.blocked || !strings.Contains(s.Reason, c.reason) {
			t.Errorf("%s: %+v", name, s)
		}
	}
}

func TestFixNamesTheCommands(t *testing.T) {
	fix := Fix(exe, 63426)
	for _, want := range []string{"tarion firewall allow", "localport=63426", `program="` + exe + `"`, "tarion portmap"} {
		if !strings.Contains(fix, want) {
			t.Errorf("fix lacks %q:\n%s", want, fix)
		}
	}
}

func TestApplyCommandsStayNarrow(t *testing.T) {
	allow := ApplyCommands(exe, 63426, false)
	if len(allow) != 2 {
		t.Fatalf("allow: %q", allow)
	}
	del, add := strings.Join(allow[0], " "), strings.Join(allow[1], " ")
	if !strings.Contains(del, "delete rule name=all dir=in program="+exe) {
		t.Errorf("must only delete this program's inbound rules: %s", del)
	}
	for _, want := range []string{"dir=in", "action=allow", "protocol=UDP", "localport=63426", "program=" + exe, "name=Tarion chat (UDP 63426)"} {
		if !strings.Contains(add, want) {
			t.Errorf("rule lacks %q: %s", want, add)
		}
	}
	if rm := ApplyCommands(exe, 63426, true); len(rm) != 1 || rm[0][2] != "delete" {
		t.Fatalf("remove must only delete: %q", rm)
	}
}

// TestCheckReadsThisMachine runs the real check: on Windows it must be able
// to read the firewall (it needs no administrator rights).
func TestCheckReadsThisMachine(t *testing.T) {
	self, _ := os.Executable()
	s := Check(self, 63426)
	if runtime.GOOS != "windows" {
		if s.Known {
			t.Fatal("only Windows is checked")
		}
		return
	}
	if !s.Known {
		t.Fatalf("check failed: %v", s.Err)
	}
	t.Logf("this machine: %+v", s)
}
