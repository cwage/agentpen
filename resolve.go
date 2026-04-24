package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// resolveCommand looks up cmd[0] on the host PATH (when not already a path),
// follows symlinks to the real binary, and reports any directories the
// sandbox must bind RO so both the invocation path and its target are
// reachable inside.
//
// Why: user-local installs on FHS distros (e.g., the native Claude installer
// puts the binary at ~/.local/bin/claude → ~/.local/share/claude/versions/X)
// would otherwise disappear when the sandbox tmpfs's $HOME. The NixOS layout
// bind-mounts /nix/store, so this was invisible until FHS hosts arrived.
func resolveCommand(cmd []string, layout HostLayout) ([]string, []string, error) {
	if len(cmd) == 0 {
		return nil, nil, fmt.Errorf("empty command")
	}
	bin := cmd[0]
	if !strings.Contains(bin, "/") {
		resolved, err := exec.LookPath(bin)
		if err != nil {
			return nil, nil, fmt.Errorf("%q not found on PATH", bin)
		}
		bin = resolved
	}
	absBin, err := filepath.Abs(bin)
	if err != nil {
		return nil, nil, fmt.Errorf("abs %s: %w", bin, err)
	}
	real, err := filepath.EvalSymlinks(absBin)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve symlinks for %s: %w", absBin, err)
	}

	seen := map[string]bool{}
	var extras []string
	for _, d := range []string{filepath.Dir(absBin), filepath.Dir(real)} {
		d = filepath.Clean(d)
		if seen[d] || coveredBy(d, layout.ReadOnlyBinds) {
			continue
		}
		seen[d] = true
		extras = append(extras, d)
	}

	return append([]string{absBin}, cmd[1:]...), extras, nil
}

// coveredBy reports whether path is inside or equal to any of prefixes,
// respecting path boundaries (so "/usrlib" is not "covered" by "/usr").
func coveredBy(path string, prefixes []string) bool {
	path = filepath.Clean(path)
	for _, p := range prefixes {
		p = filepath.Clean(p)
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}
