package main

import (
	"runtime"
	"strings"
	"testing"
)

func TestRequiredFor_Untrusted(t *testing.T) {
	// The untrusted profile is the only one shipping; every layer below must
	// be required (no silent degradation). If this test fails because a new
	// capability was added or removed, update the expected set AND think hard
	// about whether it should be required or optional.
	req := requiredFor("untrusted")
	want := []string{"bwrap", "pasta", "ip", "seccomp"}
	if len(req) != len(want) {
		t.Errorf("untrusted requires %d caps, want %d: got %v", len(req), len(want), req)
	}
	for _, w := range want {
		if !req[w] {
			t.Errorf("untrusted profile missing required capability %q", w)
		}
	}
}

func TestRequiredFor_UnknownProfile(t *testing.T) {
	if req := requiredFor("nonexistent"); req != nil {
		t.Errorf("unknown profile should return nil, got %v", req)
	}
	// paranoid is stubbed (returns nil) until implemented; keep this test so
	// we revisit it when paranoid lands.
	if req := requiredFor("paranoid"); req != nil {
		t.Errorf("paranoid profile currently stubbed, got %v", req)
	}
}

func TestCapabilities_Has(t *testing.T) {
	caps := Capabilities{
		{Name: "bwrap", Available: true},
		{Name: "ip", Available: false, Reason: "not found"},
	}
	if !caps.Has("bwrap") {
		t.Error("Has(bwrap) should be true")
	}
	if caps.Has("ip") {
		t.Error("Has(ip) should be false when Available=false")
	}
	if caps.Has("nonexistent") {
		t.Error("Has(nonexistent) should be false")
	}
}

func TestCapabilities_ValidateFor_ReportsAllMissing(t *testing.T) {
	// ValidateFor must surface every missing required capability in one shot,
	// not fail on the first. Otherwise users fix one layer, re-run, fail on
	// the next, fix that, re-run, etc. — terrible UX.
	caps := Capabilities{
		{Name: "bwrap", Available: false, Reason: "bwrap not found in PATH"},
		{Name: "pasta", Available: false, Reason: "pasta not found in PATH"},
		{Name: "ip", Available: true},
		{Name: "seccomp", Available: true},
	}
	err := caps.ValidateFor("untrusted")
	if err == nil {
		t.Fatal("expected error when required caps missing")
	}
	msg := err.Error()
	if !strings.Contains(msg, "bwrap") {
		t.Errorf("error should mention missing bwrap: %v", err)
	}
	if !strings.Contains(msg, "pasta") {
		t.Errorf("error should mention missing pasta: %v", err)
	}
}

func TestCapabilities_ValidateFor_IgnoresOptional(t *testing.T) {
	// A capability that isn't required by the profile can be missing without
	// failing validation. (None are currently optional for untrusted, so we
	// use an unknown profile which has no required caps.)
	caps := Capabilities{
		{Name: "bwrap", Available: false, Reason: "missing"},
	}
	if err := caps.ValidateFor("nonexistent"); err != nil {
		t.Errorf("unknown profile should validate trivially, got %v", err)
	}
}

func TestCapabilities_ValidateFor_AllPresent(t *testing.T) {
	caps := Capabilities{
		{Name: "bwrap", Available: true},
		{Name: "pasta", Available: true},
		{Name: "ip", Available: true},
		{Name: "seccomp", Available: true},
	}
	if err := caps.ValidateFor("untrusted"); err != nil {
		t.Errorf("all present but ValidateFor returned %v", err)
	}
}

func TestCapabilities_Report_StatusMarkers(t *testing.T) {
	caps := Capabilities{
		{Name: "bwrap", Description: "d1", Available: true},
		{Name: "ip", Description: "d2", Available: false, Reason: "missing"},
		{Name: "pretend", Description: "d3", Available: false, Reason: "nope"},
	}
	// "pretend" is not in the untrusted required set → [opt].
	r := caps.Report("untrusted")
	if !strings.Contains(r, "[ok]") {
		t.Error("report missing [ok] marker for available cap")
	}
	if !strings.Contains(r, "[MISS]") {
		t.Error("report missing [MISS] marker for required-missing cap")
	}
	if !strings.Contains(r, "[opt]") {
		t.Error("report missing [opt] marker for non-required missing cap")
	}
	if !strings.Contains(r, "missing") {
		t.Error("report should include reason for missing caps")
	}
	if !strings.Contains(r, "profile: untrusted") {
		t.Error("report header should name the profile")
	}
}

func TestDetectCapabilities_ReturnsAllKnownNames(t *testing.T) {
	// Don't depend on what's installed on the test host — just assert shape.
	caps := detectCapabilities()
	want := []string{"bwrap", "pasta", "ip", "seccomp"}
	for _, w := range want {
		found := false
		for _, c := range caps {
			if c.Name == w {
				found = true
				// Every entry must have a description for the report.
				if c.Description == "" {
					t.Errorf("cap %s has empty description", w)
				}
				break
			}
		}
		if !found {
			t.Errorf("detectCapabilities missing %q", w)
		}
	}
}

func TestDetectCapabilities_SeccompArchGate(t *testing.T) {
	// The seccomp filter is currently amd64-only. On non-amd64 hosts the
	// capability must be reported as unavailable with a clear reason.
	caps := detectCapabilities()
	var seccomp *Capability
	for i := range caps {
		if caps[i].Name == "seccomp" {
			seccomp = &caps[i]
			break
		}
	}
	if seccomp == nil {
		t.Fatal("seccomp capability not found")
	}
	if runtime.GOARCH == "amd64" {
		if !seccomp.Available {
			t.Errorf("seccomp should be Available on amd64, reason: %q", seccomp.Reason)
		}
	} else {
		if seccomp.Available {
			t.Errorf("seccomp reported Available on %s, should be gated", runtime.GOARCH)
		}
		if !strings.Contains(seccomp.Reason, "amd64") {
			t.Errorf("seccomp unavailable reason should mention amd64: %q", seccomp.Reason)
		}
	}
}
