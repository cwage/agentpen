package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
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

// newNetns derives a per-session /24 from the pid's third octet so two
// concurrent agentpen runs don't both claim 10.200.99.0/24 — the host would
// end up with two directly-connected routes for the same subnet and reply
// packets would coin-flip between the veths. 254 buckets is plenty for any
// realistic concurrency on a workstation; collision across generations is
// naturally resolved by the startup reaper (dead session's netns gets torn
// down before a new one tries the same octet).
func newNetns(pid int) Netns {
	octet := (pid % 254) + 1
	prefix := fmt.Sprintf("10.200.%d", octet)
	suffix := strconv.Itoa(pid)
	return Netns{
		Name:   "ap-" + suffix,
		HostIP: prefix + ".1",
		SbxIP:  prefix + ".2",
		Subnet: prefix + ".0/24",
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
	// Reject non-allowed TCP with RST so callers fail in milliseconds instead
	// of sitting in the kernel's ~75s SYN-retry window. Non-TCP falls through
	// to policy drop (DNS is already blocked at resolv.conf, so rare).
	b.WriteString("        meta l4proto tcp reject with tcp reset\n")
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

// teardown removes the netns, host-side veth, and MASQUERADE rule. Returns
// an aggregated error if any step failed; callers doing cleanup-on-exit
// typically discard it, but the reaper uses it to avoid claiming success
// on partial failures.
func (n *Netns) teardown() error {
	var errs []error
	if err := sudoRunQuiet("ip", "netns", "del", n.Name); err != nil {
		errs = append(errs, fmt.Errorf("del netns: %w", err))
	}
	if err := sudoRunQuiet("ip", "link", "del", n.VethH); err != nil {
		errs = append(errs, fmt.Errorf("del veth: %w", err))
	}
	if err := sudoRunQuiet("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-s", n.Subnet, "-j", "MASQUERADE"); err != nil {
		errs = append(errs, fmt.Errorf("del masquerade: %w", err))
	}
	return errors.Join(errs...)
}

// parseOrphanCandidates extracts candidate pids from `ip netns list` output.
// Skips blank lines, non-`ap-*` names, and `ap-*` names whose suffix isn't
// an integer. Pure for easy testing.
func parseOrphanCandidates(listing string) []int {
	var pids []int
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if !strings.HasPrefix(name, "ap-") {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimPrefix(name, "ap-"))
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}

// isAgentpenAlive returns true iff /proc/<pid>/comm reads as "agentpen".
// Returning true on ambiguous errors (hidepid, transient I/O) is the
// fail-safe choice — better to leak a namespace than wrongly tear down a
// live session. Only treats os.ErrNotExist as definitively dead.
func isAgentpenAlive(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(data)) == "agentpen"
}

// reapOrphans walks `ip netns list`, finds any `ap-<pid>` namespaces whose
// owning agentpen process no longer exists, and tears them down (netns +
// host veth + MASQUERADE rule). Required because defer-based teardown
// doesn't run on SIGKILL, power loss, or panic — leaked veths with
// duplicate IPs on the host would otherwise break the next session's
// return-path routing.
//
// Caller must have a valid sudo ticket. Runs the listing under sudo too,
// since some hardened distros restrict /var/run/netns. Returns only
// namespaces whose teardown fully succeeded; per-namespace failures are
// logged to stderr so partial reap is visible.
func reapOrphans() ([]string, error) {
	out, err := exec.Command("sudo", "-n", "ip", "netns", "list").Output()
	if err != nil {
		return nil, fmt.Errorf("list netns: %w", err)
	}
	var reaped []string
	for _, pid := range parseOrphanCandidates(string(out)) {
		if isAgentpenAlive(pid) {
			continue
		}
		ns := newNetns(pid)
		if err := ns.teardown(); err != nil {
			fmt.Fprintf(os.Stderr, "agentpen: reap %s: %v\n", ns.Name, err)
			continue
		}
		reaped = append(reaped, ns.Name)
	}
	return reaped, nil
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
