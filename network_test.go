package main

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestNewNetns_PidToSubnetBucketing(t *testing.T) {
	// Maps pid → third octet via (pid%254)+1. Not globally unique (PIDs
	// differing by 254 collide) — the reaper prevents cross-generation
	// collisions in practice.
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

func TestNewNetns_AdjacentPidsDistinct(t *testing.T) {
	// Adjacent pids must end up on different subnets — this is what actually
	// matters in practice, since concurrent agentpen sessions started in the
	// same shell/script will have near-sequential pids.
	a := newNetns(1000)
	b := newNetns(1001)
	if a.Subnet == b.Subnet {
		t.Fatalf("adjacent PIDs collided on %s", a.Subnet)
	}
}

func TestParseOrphanCandidates(t *testing.T) {
	cases := map[string]struct {
		input string
		want  []int
	}{
		"empty":         {input: "", want: nil},
		"blank-lines":   {input: "\n\n\n", want: nil},
		"single-plain":  {input: "ap-12345\n", want: []int{12345}},
		"with-id-suffix": {
			input: "ap-12345 (id: 10)\nap-99 (id: 4)\n",
			want:  []int{12345, 99},
		},
		"mixed-non-ap": {
			input: "default\nap-42 (id: 1)\nnetns-other\nap-7\n",
			want:  []int{42, 7},
		},
		"malformed-suffix": {
			input: "ap-notanumber\nap-\nap-123foo\nap-5\n",
			want:  []int{5},
		},
		"trailing-whitespace": {
			input: "  ap-9\t(id: 3)   \n",
			want:  []int{9},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := parseOrphanCandidates(c.input)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("parseOrphanCandidates() = %v, want %v", got, c.want)
			}
		})
	}
}
