package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestCoveredBy(t *testing.T) {
	prefixes := []string{"/usr", "/bin", "/nix/store"}
	cases := map[string]bool{
		"/usr/bin":                  true,
		"/usr":                      true,
		"/bin/bash":                 true,
		"/nix/store/abc-foo/bin":    true,
		"/usrlib":                   false, // boundary: "/usrlib" is not under "/usr"
		"/home/alice/.local/bin":    false,
		"/opt/tool":                 false,
	}
	for path, want := range cases {
		if got := coveredBy(path, prefixes); got != want {
			t.Errorf("coveredBy(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestResolveCommand_SymlinkToUserLocal(t *testing.T) {
	// Build a synthetic user-local install: $TMP/bin/tool -> $TMP/share/tool/versions/X
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	shareDir := filepath.Join(tmp, "share", "tool", "versions")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(shareDir, 0755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(shareDir, "1.0.0")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(binDir, "tool")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	layout := HostLayout{ReadOnlyBinds: []string{"/usr", "/bin", "/lib", "/lib64"}}

	// Invoke by absolute path: must rewrite to absBin and auto-mount both parents.
	got, mounts, err := resolveCommand([]string{link, "--flag"}, layout)
	if err != nil {
		t.Fatalf("resolveCommand: %v", err)
	}
	wantCmd := []string{link, "--flag"}
	if !reflect.DeepEqual(got, wantCmd) {
		t.Errorf("command = %v, want %v", got, wantCmd)
	}
	sort.Strings(mounts)
	wantMounts := []string{binDir, shareDir}
	sort.Strings(wantMounts)
	if !reflect.DeepEqual(mounts, wantMounts) {
		t.Errorf("mounts = %v, want %v", mounts, wantMounts)
	}
}

func TestResolveCommand_SystemBinary(t *testing.T) {
	// A binary under a covered layout dir should produce zero auto-mounts.
	// Explicit layout covering FHS (/bin/sh, /usr/bin/sh), Nix store targets
	// (/nix/store/...), and NixOS runtime prefixes (/run/current-system/sw/bin/sh,
	// /run/wrappers/...) so the test is deterministic on all three host shapes.
	layout := HostLayout{ReadOnlyBinds: []string{
		"/usr",
		"/bin",
		"/nix/store",
		"/run/current-system",
		"/run/wrappers",
	}}
	got, mounts, err := resolveCommand([]string{"sh"}, layout)
	if err != nil {
		t.Skipf("sh not on PATH in this env: %v", err)
	}
	if !filepath.IsAbs(got[0]) {
		t.Errorf("command[0] not absolute: %q", got[0])
	}
	if len(mounts) != 0 {
		t.Errorf("expected no auto-mounts for system binary, got %v", mounts)
	}
}

func TestResolveCommand_NotOnPath(t *testing.T) {
	layout := HostLayout{}
	_, _, err := resolveCommand([]string{"definitely-not-a-real-binary-zzz"}, layout)
	if err == nil {
		t.Fatal("expected error for missing binary, got nil")
	}
}
