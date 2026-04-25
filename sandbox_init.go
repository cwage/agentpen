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
	sandboxGatewayIP   = "192.0.2.1" // RFC 5737 documentation prefix
	sandboxOwnIP       = "192.0.2.2"
	sandboxNetMaskBits = 29
	forwarderListen    = "127.0.0.1:443"
)

// runSandboxInit runs inside pasta's userns+netns. It:
//   1. brings up lo and eth0 with our pinned address and a /32 route to the gateway,
//   2. starts the forwarder as a separate process. The forwarder runs at the
//      same kernel-side uid as the user's code (pasta's userns maps only one
//      uid), which means user code can SIGKILL it — accepted self-DoS, not
//      a privilege boundary violation. See spawnForwarder.
//   3. exec's the supplied inner command (typically a bash wrapper that opens
//      the seccomp BPF as FD 3 and exec's bwrap).
//
// Argv shape:
//   agentpen __sandbox-init <proxy-port> -- <prog> [<args>...]
//
// We hold all caps here (userns-root in pasta's userns), so ip(8) calls and
// the forwarder spawn need no extra privilege.
func runSandboxInit(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: agentpen __sandbox-init <proxy-port> -- <prog> [args...]")
	}
	port, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid proxy port %q: %w", args[0], err)
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

func configureNetns() error {
	iface, err := findSandboxIface()
	if err != nil {
		return err
	}
	steps := [][]string{
		// lo is down by default in a fresh netns. The forwarder binds 127.0.0.1
		// and user code dials 127.0.0.1; both fail without this.
		{"ip", "link", "set", "lo", "up"},
		{"ip", "link", "set", iface, "up"},
		{"ip", "addr", "add", sandboxOwnIP + "/32", "dev", iface},
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
// waits briefly for it to bind. The forwarder runs at the same uid as the
// user's code (kernel-side) — pasta's userns maps only one uid, so we can't
// give it a distinct identity without /etc/subuid setup. Means user code
// can SIGKILL it and self-DoS its own outbound. Documented limitation; not
// a privilege boundary violation since the forwarder cannot route anywhere
// the kernel /32 route + SNI proxy don't already gate.
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
	// Brief readiness wait. We try to dial the listener; the child either
	// exits on bind failure (we surface it) or starts accepting (we proceed).
	deadline := time.Now().Add(2 * time.Second)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("forwarder did not bind %s in time", listen)
		}
		c, err := net.DialTimeout("tcp", listen, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}
