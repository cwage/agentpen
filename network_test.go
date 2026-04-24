package main

import (
	"strconv"
	"strings"
	"testing"
)

func TestNewNetns_UniqueSubnetPerPid(t *testing.T) {
	cases := []struct {
		pid      int
		wantOct  int
		wantName string
	}{
		{1, 2, "ap-1"},
		{99, 100, "ap-99"},
		{253, 254, "ap-253"},
		{254, 1, "ap-254"}, // wraps
		{12345, (12345 % 254) + 1, "ap-12345"},
	}
	for _, c := range cases {
		ns := newNetns(c.pid)
		if ns.Name != c.wantName {
			t.Errorf("pid %d: Name = %q, want %q", c.pid, ns.Name, c.wantName)
		}
		wantPrefix := "10.200." + strconv.Itoa(c.wantOct) + "."
		if !strings.HasPrefix(ns.Subnet, wantPrefix) {
			t.Errorf("pid %d: Subnet = %q, want prefix %q", c.pid, ns.Subnet, wantPrefix)
		}
		if ns.HostIP != wantPrefix+"1" {
			t.Errorf("pid %d: HostIP = %q, want %s1", c.pid, ns.HostIP, wantPrefix)
		}
		if ns.SbxIP != wantPrefix+"2" {
			t.Errorf("pid %d: SbxIP = %q, want %s2", c.pid, ns.SbxIP, wantPrefix)
		}
	}
}

func TestNewNetns_DistinctConcurrentPids(t *testing.T) {
	// Two live sessions with different PIDs must land on different subnets.
	a := newNetns(1000)
	b := newNetns(1001)
	if a.Subnet == b.Subnet {
		t.Fatalf("adjacent PIDs collided on %s", a.Subnet)
	}
}
