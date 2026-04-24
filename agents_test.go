package main

import (
	"sort"
	"strings"
	"testing"
)

func TestKnownAgents_CoversExpected(t *testing.T) {
	// If this test fails because an agent was removed, update it. If it fails
	// because an agent was renamed silently, that's a bug: README/help/docs
	// advertise these names.
	expected := []string{"claude", "codex", "aider", "opencode"}
	got := knownAgents()
	sort.Strings(got)
	sort.Strings(expected)

	for _, want := range expected {
		found := false
		for _, g := range got {
			if g == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected agent %q missing from knownAgents: got %v", want, got)
		}
	}
}

func TestKnownAgents_MatchesRegistry(t *testing.T) {
	if len(knownAgents()) != len(agents) {
		t.Errorf("knownAgents() returned %d names but registry has %d",
			len(knownAgents()), len(agents))
	}
}

func TestAgentsRegistry_NoEmptyAllowlists(t *testing.T) {
	// Zero AllowedHosts would mean the agent can reach nothing — likely a
	// misconfiguration, and one that produces silent failures inside the
	// sandbox. Catch it at test time.
	for name, a := range agents {
		if len(a.AllowedHosts) == 0 {
			t.Errorf("agent %q has empty AllowedHosts", name)
		}
	}
}

func TestAgentsRegistry_MountPathsWellFormed(t *testing.T) {
	// Mount paths go through expandTilde then Stat. Anything that isn't
	// absolute or starts with "~/" is a typo (e.g., ".config/foo" would
	// stat against CWD at invocation time, which is the project dir — bad).
	for name, a := range agents {
		for _, m := range a.Mounts {
			if !strings.HasPrefix(m, "/") && !strings.HasPrefix(m, "~/") {
				t.Errorf("agent %q mount %q is neither absolute nor ~/... — typo?",
					name, m)
			}
		}
	}
}

func TestAgentsRegistry_EnvVarsLookLikeEnvNames(t *testing.T) {
	// Env var names should be [A-Z0-9_]+ — guard against accidentally listing
	// a value or a path.
	for name, a := range agents {
		for _, v := range a.EnvVars {
			if v == "" {
				t.Errorf("agent %q has empty env var name", name)
				continue
			}
			for _, r := range v {
				if !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '_' {
					t.Errorf("agent %q env var %q has non-[A-Z0-9_] char %q", name, v, r)
					break
				}
			}
		}
	}
}
