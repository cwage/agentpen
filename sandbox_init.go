package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Network constants for the pasta-managed namespace. Pasta is configured
// with these via -a/-g/-n on the launcher side; here we reapply them inside
// the namespace because we run pasta with --no-dhcp (DHCP would require an
// extra client process inside; it's cleaner to configure statically).
const (
	sandboxGatewayIP = "192.0.2.1" // RFC 5737 documentation prefix
	sandboxOwnIP     = "192.0.2.2"
	// /32 matches the in-namespace config (single-host route to gateway only)
	// so pasta's view doesn't install a connected route for 192.0.2.0/29 that
	// would weaken the "no route to host except gateway" property.
	sandboxNetMaskBits = 32
	forwarderListen    = "127.0.0.1:443"
)

// runSandboxInit runs inside pasta's userns+netns. It:
//   1. brings up lo and the namespace's tap interface (whose name pasta picks
//      after the host's outbound interface — we discover it via findSandboxIface
//      rather than hardcoding) with our pinned address and a /32 route to
//      the gateway,
//   2. installs an nft egress filter so the only reachable host-side endpoint
//      is the SNI proxy port (without this, pasta's --map-host-loopback would
//      let the sandbox dial any port on the host's 127.0.0.1 — every dev
//      service, every database, every IPC-as-TCP socket),
//   3. starts the forwarder as a separate process,
//   4. exec's the supplied inner command (typically a /bin/sh wrapper that
//      opens the seccomp BPF as FD 3 and exec's bwrap).
//
// Argv shape:
//   agentpen __sandbox-init <proxy-port> -- <prog> [<args>...]
//
// We hold all caps here (userns-root in pasta's userns), so ip(8), nft(8) and
// the forwarder spawn need no extra privilege. CAP_NET_ADMIN is dropped by
// bwrap before user code runs, locking the rules in place.
func runSandboxInit(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: agentpen __sandbox-init <proxy-port> -- <prog> [args...]")
	}
	port, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid proxy port %q: %w", args[0], err)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("proxy port out of range: %d", port)
	}
	rest := args[1:]
	if len(rest) == 0 || rest[0] != "--" {
		return fmt.Errorf("expected `--` separator before inner command")
	}
	rest = rest[1:]
	if len(rest) == 0 {
		return fmt.Errorf("missing inner command")
	}

	if err := configureNetns(); err != nil {
		return fmt.Errorf("netns config: %w", err)
	}
	if err := installEgressFilter(port); err != nil {
		return fmt.Errorf("egress filter: %w", err)
	}

	upstream := net.JoinHostPort(sandboxGatewayIP, strconv.Itoa(port))
	if err := spawnForwarder(forwarderListen, upstream); err != nil {
		return fmt.Errorf("spawn forwarder: %w", err)
	}

	prog, err := exec.LookPath(rest[0])
	if err != nil {
		return fmt.Errorf("locate %s: %w", rest[0], err)
	}
	// syscall.Exec replaces this process; the forwarder (already a separate
	// process) keeps running until pasta's pidns is torn down.
	return syscall.Exec(prog, rest, os.Environ())
}

// egressFilterRules returns the nft ruleset that gates outbound traffic to
// the host. Without this, pasta's --map-host-loopback gives the sandbox TCP
// reachability to every port on the host's 127.0.0.1 (databases, dev
// servers, SSH, IPC-over-TCP), not just the SNI proxy. Pure function so the
// rule text is unit-testable.
func egressFilterRules(proxyPort int) string {
	return fmt.Sprintf(`table inet agentpen {
    chain output {
        type filter hook output priority 0; policy drop;
        ct state established,related accept
        oifname "lo" accept
        ip daddr %s tcp dport %d accept
        meta l4proto tcp reject with tcp reset
    }
}
`, sandboxGatewayIP, proxyPort)
}

// installEgressFilter applies the egress nft ruleset inside the current
// netns. nft inside an unprivileged userns just needs CAP_NET_ADMIN within
// that userns — which we hold here as the userns root — so this runs
// without sudo and only affects the sandbox's tables.
func installEgressFilter(proxyPort int) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(egressFilterRules(proxyPort))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft load: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func configureNetns() error {
	iface, err := findSandboxIface()
	if err != nil {
		return err
	}
	addrCIDR := fmt.Sprintf("%s/%d", sandboxOwnIP, sandboxNetMaskBits)
	steps := [][]string{
		// lo is down by default in a fresh netns. The forwarder binds 127.0.0.1
		// and user code dials 127.0.0.1; both fail without this.
		{"ip", "link", "set", "lo", "up"},
		{"ip", "link", "set", iface, "up"},
		{"ip", "addr", "add", addrCIDR, "dev", iface},
		{"ip", "route", "add", sandboxGatewayIP, "dev", iface},
	}
	for _, s := range steps {
		out, err := exec.Command(s[0], s[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w (%s)", strings.Join(s, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// findSandboxIface returns the name of the non-loopback interface in the
// current netns. Pasta creates exactly one tap and names it after the host's
// outbound interface by default (eno1, enp3s0, eth0, wlan0, …) — host-
// dependent, so we discover the name at runtime instead of hardcoding it.
func findSandboxIface() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list interfaces: %w", err)
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		return i.Name, nil
	}
	return "", fmt.Errorf("no non-loopback interface in sandbox netns")
}

// spawnForwarder launches `agentpen __forwarder` as a separate process and
// waits briefly for it to bind. The forwarder runs in pasta's pid namespace;
// bwrap's --unshare-pid puts user code in a child pid ns where the
// forwarder's pid isn't visible, so user code can't signal or inspect it.
//
// Readiness is racey: dial-loop until the listener accepts, child Wait() in
// parallel — if the child exits before binding (e.g. EADDRINUSE), we surface
// its real error instead of letting the dial loop run out the clock with a
// generic "did not bind in time" message.
func spawnForwarder(listen, upstream string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}
	cmd := exec.Command(self, "__forwarder", listen, upstream)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	childExit := make(chan error, 1)
	go func() { childExit <- cmd.Wait() }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-childExit:
			if err == nil {
				return fmt.Errorf("forwarder exited before binding %s", listen)
			}
			return fmt.Errorf("forwarder exited before binding %s: %w", listen, err)
		default:
		}
		c, err := net.DialTimeout("tcp", listen, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("forwarder did not bind %s in time", listen)
}
