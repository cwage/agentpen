package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Netns encapsulates the network namespace + filtering state for one sandbox run.
type Netns struct {
	Name   string
	HostIP string
	SbxIP  string
	Subnet string
	VethH  string
	VethS  string
}

func newNetns(suffix string) Netns {
	return Netns{
		Name:   "ap-" + suffix,
		HostIP: "10.200.99.1",
		SbxIP:  "10.200.99.2",
		Subnet: "10.200.99.0/24",
		VethH:  "vh-" + suffix,
		VethS:  "vs-" + suffix,
	}
}

// resolveHosts returns all IPv4 addresses for the given hostnames.
func resolveHosts(hosts []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, h := range hosts {
		ips, err := net.LookupIP(h)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", h, err)
		}
		for _, ip := range ips {
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			s := v4.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// setup creates the netns, veth pair, NAT rule, and loads the nft allowlist.
// Every command runs via sudo. Caller is responsible for teardown().
func (n *Netns) setup(allowedIPs []string) error {
	steps := [][]string{
		{"ip", "netns", "add", n.Name},
		{"ip", "link", "add", n.VethH, "type", "veth", "peer", "name", n.VethS},
		{"ip", "link", "set", n.VethS, "netns", n.Name},
		{"ip", "addr", "add", n.HostIP + "/24", "dev", n.VethH},
		{"ip", "link", "set", n.VethH, "up"},
		{"ip", "-n", n.Name, "addr", "add", n.SbxIP + "/24", "dev", n.VethS},
		{"ip", "-n", n.Name, "link", "set", n.VethS, "up"},
		{"ip", "-n", n.Name, "link", "set", "lo", "up"},
		{"ip", "-n", n.Name, "route", "add", "default", "via", n.HostIP},
		{"sysctl", "-q", "-w", "net.ipv4.ip_forward=1"},
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", n.Subnet, "-j", "MASQUERADE"},
	}
	for _, s := range steps {
		if err := sudoRun(s...); err != nil {
			return fmt.Errorf("netns setup (%s): %w", strings.Join(s, " "), err)
		}
	}
	return n.loadNft(allowedIPs)
}

func (n *Netns) loadNft(allowedIPs []string) error {
	var b strings.Builder
	b.WriteString("table inet agentpen {\n")
	b.WriteString("    chain output {\n")
	b.WriteString("        type filter hook output priority 0; policy drop;\n")
	b.WriteString("        ct state established,related accept\n")
	b.WriteString("        ip daddr 127.0.0.0/8 accept\n")
	for _, ip := range allowedIPs {
		fmt.Fprintf(&b, "        ip daddr %s accept\n", ip)
	}
	b.WriteString("    }\n")
	b.WriteString("}\n")

	f, err := os.CreateTemp("", "agentpen-nft-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return err
	}
	f.Close()

	return sudoRun("ip", "netns", "exec", n.Name, "nft", "-f", f.Name())
}

// teardown is best-effort and swallows errors (cleanup should never fail the run).
func (n *Netns) teardown() {
	_ = sudoRunQuiet("ip", "netns", "del", n.Name)
	_ = sudoRunQuiet("ip", "link", "del", n.VethH)
	_ = sudoRunQuiet("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", n.Subnet, "-j", "MASQUERADE")
}

// sudoRun runs `sudo <args...>` with inherited stdio.
func sudoRun(args ...string) error {
	cmd := exec.Command("sudo", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// sudoRunQuiet runs with -n (no password prompt) and discards output; used for cleanup.
func sudoRunQuiet(args ...string) error {
	full := append([]string{"-n"}, args...)
	cmd := exec.Command("sudo", full...)
	return cmd.Run()
}
