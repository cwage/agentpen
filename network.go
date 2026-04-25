package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// pastaArgs returns the pasta(1) command line for launching the sandbox.
// We pin RFC 5737 documentation addresses so the inner __sandbox-init code
// doesn't have to discover what pasta picked from the host's interface, and
// disable DHCP/NDP since we configure the namespace statically.
//
// --map-host-loopback: connections to the gateway address inside the
//   namespace reach the host's loopback (where the SNI proxy listens).
// --no-dhcp / --no-ndp / --no-dhcpv6 / --no-ra: suppress all auto-config;
//   we set everything by hand inside the namespace for determinism.
// -t/-u/-T/-U none: disable pasta's auto port-forwarding. Defaults are
//   `auto`, which scans /proc/net/{tcp,tcp6,udp,udp6} for bound ports —
//   that scan logs `lseek() failed on /proc/net file: Illegal seek` once
//   per probe on older kernels (e.g. Ubuntu 22.04). We don't want any
//   forwarding anyway: the in-namespace forwarder + nft handle inbound,
//   and nothing in the namespace should be reachable from the host.
// -q: don't print pasta's startup banner on every run.
// -f: foreground; pasta exits when its child does, which we want for clean
//   teardown of the namespace and the in-namespace forwarder.
func pastaArgs(proxyPort int, selfPath string, bwrapArgv []string) []string {
	args := []string{
		"-q", "-f",
		"--no-dhcp", "--no-dhcpv6", "--no-ndp", "--no-ra",
		"-t", "none", "-u", "none", "-T", "none", "-U", "none",
		// Don't pin the namespace interface name — pasta names the tap after
		// the host's outbound interface (eno1, enp3s0, wlan0, eth0, …) and
		// we discover whatever it picked from inside the namespace at runtime.
		"-a", sandboxOwnIP, "-n", fmt.Sprintf("%d", sandboxNetMaskBits), "-g", sandboxGatewayIP,
		"--map-host-loopback", sandboxGatewayIP,
		"--",
		selfPath, "__sandbox-init", fmt.Sprintf("%d", proxyPort), "--",
	}
	return append(args, bwrapArgv...)
}

// runPasta launches pasta with the given bwrap argv inside, plumbing stdio
// through. Returns the child's exit code (or -1 on launch error).
//
// If the child terminates by signal we map to the conventional 128+signum
// exit code instead of letting *exec.ExitError's ExitCode() return -1, which
// would otherwise propagate as os.Exit(255) and lose all signal context.
func runPasta(proxyPort int, bwrapArgv []string) (int, error) {
	pasta, err := exec.LookPath("pasta")
	if err != nil {
		return -1, fmt.Errorf("pasta: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return -1, fmt.Errorf("locate self: %w", err)
	}
	cmd := exec.Command(pasta, pastaArgs(proxyPort, self, bwrapArgv)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			return -1, err
		}
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return exit.ExitCode(), nil
	}
	return 0, nil
}
