package main

import (
	"fmt"
	"os"
	"os/exec"
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
// -q: don't print pasta's startup banner on every run.
// -f: foreground; pasta exits when its child does, which we want for clean
//   teardown of the namespace and the in-namespace forwarder.
func pastaArgs(proxyPort int, selfPath string, bwrapArgv []string) []string {
	args := []string{
		"-q", "-f",
		"--no-dhcp", "--no-dhcpv6", "--no-ndp", "--no-ra",
		"-a", sandboxOwnIP, "-n", "29", "-g", sandboxGatewayIP,
		"--map-host-loopback", sandboxGatewayIP,
		"--",
		selfPath, "__sandbox-init", fmt.Sprintf("%d", proxyPort), "--",
	}
	return append(args, bwrapArgv...)
}

// runPasta launches pasta with the given bwrap argv inside, plumbing stdio
// through. Returns the child's exit code (or -1 on launch error).
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
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode(), nil
		}
		return -1, err
	}
	return 0, nil
}
