package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// stageEtc builds a per-run /etc directory copied from host /etc with pinned
// hosts entries and a blank resolv.conf. Returned path must be rm -rf'd by caller.
func stageEtc(allowedHosts []string, hostIPs map[string]string) (string, error) {
	dir, err := os.MkdirTemp("", "sbx-etc-*")
	if err != nil {
		return "", err
	}
	// Use cp -a to preserve symlinks verbatim (NixOS's /etc is a symlink farm
	// into /nix/store; writing a new /etc from scratch would be painful).
	// Swallow errors for unreadable files like /etc/shadow.
	cmd := exec.Command("cp", "-a", "/etc/.", dir+"/")
	cmd.Stderr = io.Discard
	_ = cmd.Run()

	// These are symlinks on NixOS; unlink before overwriting with regular files.
	_ = os.Remove(filepath.Join(dir, "hosts"))
	_ = os.Remove(filepath.Join(dir, "resolv.conf"))

	var hosts strings.Builder
	hosts.WriteString("127.0.0.1 localhost\n")
	for _, h := range allowedHosts {
		if ip, ok := hostIPs[h]; ok {
			fmt.Fprintf(&hosts, "%s %s\n", ip, h)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte(hosts.String()), 0644); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "resolv.conf"), []byte("# DNS blocked by sandbox\n"), 0644); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// firstIPFor returns one IPv4 per hostname, used to populate /etc/hosts.
func firstIPFor(hosts []string) map[string]string {
	out := map[string]string{}
	for _, h := range hosts {
		ips, err := resolveHosts([]string{h})
		if err != nil || len(ips) == 0 {
			continue
		}
		out[h] = ips[0]
	}
	return out
}

// bwrapArgs builds the argv to bwrap for the untrusted profile.
func bwrapArgs(cfg runConfig, stageEtcPath string) []string {
	layout := cfg.HostLayout
	shell, err := exec.LookPath("bash")
	if err != nil {
		shell = "/bin/sh"
	}
	args := []string{
		"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup",
		"--die-with-parent", "--new-session", "--hostname", "sandbox",
		"--clearenv",
		"--setenv", "HOME", cfg.Home,
		"--setenv", "USER", cfg.User,
		"--setenv", "LOGNAME", cfg.User,
		"--setenv", "SHELL", shell,
		"--setenv", "TERM", orDefault(os.Getenv("TERM"), "xterm-256color"),
		"--setenv", "PATH", layout.PathEnv,
		"--setenv", "LANG", orDefault(os.Getenv("LANG"), "C.UTF-8"),
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--tmpfs", "/run",
		"--tmpfs", cfg.Home,
		"--ro-bind", stageEtcPath, "/etc",
	}
	for _, p := range layout.ReadOnlyBinds {
		if _, err := os.Stat(p); err == nil {
			args = append(args, "--ro-bind", p, p)
		}
	}
	args = append(args, "--bind", cfg.ProjectDir, cfg.ProjectDir, "--chdir", cfg.ProjectDir)

	// Forward env vars that are set on the host
	for _, v := range cfg.EnvVars {
		if val, ok := os.LookupEnv(v); ok {
			args = append(args, "--setenv", v, val)
		}
	}

	// Agent config mounts — RW so the agent can refresh tokens / persist state.
	for _, p := range cfg.Mounts {
		expanded := expandTilde(p, cfg.Home)
		if _, err := os.Stat(expanded); err == nil {
			args = append(args, "--bind", expanded, expanded)
		}
	}

	// Explicit user --mount-rw
	for _, p := range cfg.ExtraRWMounts {
		expanded := expandTilde(p, cfg.Home)
		if _, err := os.Stat(expanded); err == nil {
			args = append(args, "--bind", expanded, expanded)
		}
	}
	// Explicit user --mount (RO)
	for _, p := range cfg.ExtraROMounts {
		expanded := expandTilde(p, cfg.Home)
		if _, err := os.Stat(expanded); err == nil {
			args = append(args, "--ro-bind", expanded, expanded)
		}
	}

	args = append(args, cfg.Command...)
	return args
}

func expandTilde(p, home string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	if p == "~" {
		return home
	}
	return p
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
