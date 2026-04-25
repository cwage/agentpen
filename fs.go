package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// stageEtc builds a per-run /etc directory copied from host /etc with pinned
// hosts entries and a blank resolv.conf. Each allowed hostname is mapped to
// 127.0.0.1 — that's the in-namespace forwarder, which splices to the SNI
// proxy on the host. Returned path must be rm -rf'd by caller.
func stageEtc(allowedHosts []string) (string, error) {
	dir, err := os.MkdirTemp("", "agentpen-etc-*")
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
		fmt.Fprintf(&hosts, "127.0.0.1 %s\n", h)
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

// bwrapArgs builds the argv to bwrap for the untrusted profile.
func bwrapArgs(cfg runConfig, stageEtcPath string) []string {
	layout := cfg.HostLayout
	shell, err := exec.LookPath("bash")
	if err != nil {
		shell = "/bin/sh"
	}
	// Follow the standard Linux .profile convention: ~/.local/bin wins over
	// system dirs when present. Lets user-local agent installs be found by
	// name inside the sandbox (the binary itself is bound via auto-mount).
	pathEnv := layout.PathEnv
	userLocalBin := filepath.Join(cfg.Home, ".local", "bin")
	if info, err := os.Stat(userLocalBin); err == nil && info.IsDir() {
		pathEnv = userLocalBin + ":" + pathEnv
	}
	args := []string{
		"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup",
		"--die-with-parent", "--new-session", "--hostname", "agentpen",
		// Pasta puts us in a userns where we're uid 0; without --uid, bwrap
		// preserves that, and agents like `claude --dangerously-skip-permissions`
		// refuse to run as root. Map back to the real host uid/gid.
		"--uid", strconv.Itoa(os.Getuid()),
		"--gid", strconv.Itoa(os.Getgid()),
		"--clearenv",
		"--setenv", "HOME", cfg.Home,
		"--setenv", "USER", cfg.User,
		"--setenv", "LOGNAME", cfg.User,
		"--setenv", "SHELL", shell,
		"--setenv", "TERM", orDefault(os.Getenv("TERM"), "xterm-256color"),
		"--setenv", "PATH", pathEnv,
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
	// Auto-mounts (from resolveCommand) bind RO before the project dir and any
	// explicit RW mounts — bwrap is order-sensitive, so later RW binds override
	// here if a caller invokes a binary from inside the project dir.
	for _, p := range cfg.AutoMounts {
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
