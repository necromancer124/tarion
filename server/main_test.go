package main

import (
	"testing"
	"time"
)

func TestHandlePacketQuerySignalsTargetToPunchRequester(t *testing.T) {
	r := newTestRegistry(t, time.Minute)
	if got := handlePacket(r, "REG|alice|secret", "198.51.100.10:40000", nil); got != "OK|REGISTERED" {
		t.Fatalf("register alice got %q", got)
	}
	if got := handlePacket(r, "REG|bob|hunter2", "203.0.113.20:63425", nil); got != "OK|REGISTERED" {
		t.Fatalf("register bob got %q", got)
	}

	var punchTarget, punchPayload string
	got := handlePacket(r, "QRY|alice|secret|bob", "198.51.100.10:40000", func(targetAddr, payload string) error {
		punchTarget, punchPayload = targetAddr, payload
		return nil
	})
	if got != "OK|ADDR|203.0.113.20:63425" {
		t.Fatalf("query response=%q", got)
	}
	if punchTarget != "203.0.113.20:63425" {
		t.Fatalf("punch target=%q", punchTarget)
	}
	if punchPayload != "PCH|alice|198.51.100.10:40000" {
		t.Fatalf("punch payload=%q", punchPayload)
	}
}

func TestHandlePacketRejectsWrongPasswordBeforeAddressUpdate(t *testing.T) {
	r := newTestRegistry(t, time.Minute)
	if got := handlePacket(r, "REG|alice|secret", "198.51.100.10:40000", nil); got != "OK|REGISTERED" {
		t.Fatalf("register got %q", got)
	}
	if got := handlePacket(r, "HBT|alice|wrong", "198.51.100.99:40000", nil); got != "ERR|AUTH_FAILED" {
		t.Fatalf("wrong password response=%q", got)
	}
	addr, err := r.GetUserAddr("alice")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "198.51.100.10:40000" {
		t.Fatalf("wrong password changed addr to %q", addr)
	}
}
