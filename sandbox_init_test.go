package main

import (
	"net"
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

func TestSelectSandboxIface(t *testing.T) {
	lo := net.Interface{Name: "lo", Flags: net.FlagLoopback | net.FlagUp}
	ip6tnl := net.Interface{Name: "ip6tnl0", Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{}}
	tunl := net.Interface{Name: "tunl0", Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{0, 0, 0, 0}}
	tap := net.Interface{Name: "wlp4s0", Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{0xf6, 0x56, 0x4a, 0xa3, 0x7c, 0x8c}}
	tap2 := net.Interface{Name: "eno1", Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}}

	cases := []struct {
		name    string
		ifs     []net.Interface
		want    string
		wantErr bool
	}{
		{"only loopback", []net.Interface{lo}, "", true},
		{"only pseudo-tunnel", []net.Interface{lo, ip6tnl}, "", true},
		{"only zero-MAC tunl0", []net.Interface{lo, tunl}, "", true},
		{"tap only", []net.Interface{lo, tap}, "wlp4s0", false},
		{"pseudo before tap (the regression)", []net.Interface{lo, ip6tnl, tap}, "wlp4s0", false},
		{"tap before pseudo", []net.Interface{lo, tap, ip6tnl}, "wlp4s0", false},
		{"multiple pseudos then tap", []net.Interface{lo, ip6tnl, tunl, tap}, "wlp4s0", false},
		{"tap named eno1", []net.Interface{lo, tap2}, "eno1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectSandboxIface(tc.ifs)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHasRealHardwareAddr(t *testing.T) {
	cases := []struct {
		name string
		hw   net.HardwareAddr
		want bool
	}{
		{"empty", net.HardwareAddr{}, false},
		{"nil", nil, false},
		{"all zero 6", net.HardwareAddr{0, 0, 0, 0, 0, 0}, false},
		{"all zero 4", net.HardwareAddr{0, 0, 0, 0}, false},
		{"real ethernet", net.HardwareAddr{0xf6, 0x56, 0x4a, 0xa3, 0x7c, 0x8c}, true},
		{"only first byte set", net.HardwareAddr{0x02, 0, 0, 0, 0, 0}, true},
		{"only last byte set", net.HardwareAddr{0, 0, 0, 0, 0, 0x01}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasRealHardwareAddr(tc.hw); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
