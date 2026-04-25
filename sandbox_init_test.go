package main

import (
	"strings"
	"testing"
)

func TestEgressFilterRules(t *testing.T) {
	rules := egressFilterRules(54321)

	mustContain := []string{
		"table inet agentpen",
		"type filter hook output priority 0; policy drop",
		"ct state established,related accept",
		`oifname "lo" accept`,
		"ip daddr " + sandboxGatewayIP + " tcp dport 54321 accept",
		"meta l4proto tcp reject with tcp reset",
	}
	for _, want := range mustContain {
		if !strings.Contains(rules, want) {
			t.Errorf("egressFilterRules missing %q\nfull rules:\n%s", want, rules)
		}
	}
}

func TestEgressFilterRules_PortIsParameterized(t *testing.T) {
	// Different ports must produce different rules; the port being a literal
	// in the chain body is the whole point.
	a := egressFilterRules(8443)
	b := egressFilterRules(9999)
	if a == b {
		t.Fatal("rules identical despite different ports")
	}
	if !strings.Contains(a, "tcp dport 8443") {
		t.Error("port 8443 rule missing 'tcp dport 8443'")
	}
	if strings.Contains(b, "tcp dport 8443") {
		t.Error("port 9999 rule still mentions 8443 — likely a hardcoded leak")
	}
}
