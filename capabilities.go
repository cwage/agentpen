package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Capability is one atomic capability the host either does or doesn't provide.
// Multiple capabilities combine into layers (e.g. network isolation needs
// pasta + bwrap + setpriv).
type Capability struct {
	Name        string
	Description string
	Available   bool
	Reason      string // why unavailable, if applicable
}

type Capabilities []Capability

func detectCapabilities() Capabilities {
	bin := func(name string) (bool, string) {
		if _, err := exec.LookPath(name); err != nil {
			return false, fmt.Sprintf("%s not found in PATH", name)
		}
		return true, ""
	}

	specs := []struct {
		name, desc string
		check      func() (bool, string)
	}{
		{"bwrap", "Filesystem & process isolation (bubblewrap)", func() (bool, string) { return bin("bwrap") }},
		{"pasta", "Userspace network namespace (passt/pasta)", func() (bool, string) { return bin("pasta") }},
		{"ip", "Configure addresses and routes inside the namespace (iproute2)", func() (bool, string) { return bin("ip") }},
		{"seccomp", "Syscall restriction via BPF", func() (bool, string) {
			if runtime.GOARCH != "amd64" {
				return false, "seccomp filter currently only generated for amd64"
			}
			return true, ""
		}},
	}

	out := make(Capabilities, len(specs))
	for i, s := range specs {
		avail, reason := s.check()
		out[i] = Capability{Name: s.name, Description: s.desc, Available: avail, Reason: reason}
	}
	return out
}

// required lists the capabilities a profile needs. Missing any of these
// causes a refuse-to-run (no silent degradation).
func requiredFor(profile string) map[string]bool {
	switch profile {
	case "untrusted":
		return map[string]bool{
			"bwrap": true, "pasta": true, "ip": true, "seccomp": true,
		}
	}
	return nil
}

func (cs Capabilities) ValidateFor(profile string) error {
	req := requiredFor(profile)
	var missing []string
	for _, c := range cs {
		if req[c.Name] && !c.Available {
			missing = append(missing, fmt.Sprintf("%s (%s)", c.Name, c.Reason))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required capabilities: %s", strings.Join(missing, "; "))
	}
	return nil
}

func (cs Capabilities) Has(name string) bool {
	for _, c := range cs {
		if c.Name == name {
			return c.Available
		}
	}
	return false
}

// Report renders a human-readable capability table.
func (cs Capabilities) Report(profile string) string {
	req := requiredFor(profile)
	var b strings.Builder
	fmt.Fprintf(&b, "host capabilities (profile: %s)\n\n", profile)
	for _, c := range cs {
		var status string
		switch {
		case c.Available:
			status = "[ok]    "
		case req[c.Name]:
			status = "[MISS]  "
		default:
			status = "[opt]   "
		}
		fmt.Fprintf(&b, "  %s%-10s %s", status, c.Name, c.Description)
		if !c.Available && c.Reason != "" {
			fmt.Fprintf(&b, " — %s", c.Reason)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n[ok] available  [MISS] required but missing  [opt] optional\n")
	return b.String()
}
