package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandTilde(t *testing.T) {
	home := "/home/alice"
	cases := map[string]string{
		"~":             "/home/alice",
		"~/":            "/home/alice",
		"~/.ssh":        "/home/alice/.ssh",
		"~/.config/foo": "/home/alice/.config/foo",
		"/etc/hosts":    "/etc/hosts",
		"relative/path": "relative/path",
		// Boundary: "~user" (no slash) is NOT expanded — only "~" and "~/..."
		"~alice": "~alice",
	}
	for in, want := range cases {
		if got := expandTilde(in, home); got != want {
			t.Errorf("expandTilde(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOrDefault(t *testing.T) {
	if got := orDefault("", "fallback"); got != "fallback" {
		t.Errorf("orDefault(\"\", fallback) = %q", got)
	}
	if got := orDefault("set", "fallback"); got != "set" {
		t.Errorf("orDefault(set, fallback) = %q", got)
	}
}

// makeExistingDirs creates a tmpdir and returns subpaths inside it.
// Lets us pass paths that os.Stat sees as real without touching the host FS.
func makeExistingDirs(t *testing.T, names ...string) (root string, paths []string) {
	t.Helper()
	root = t.TempDir()
	for _, n := range names {
		p := filepath.Join(root, n)
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	return root, paths
}

func hasFlagPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

// hasTriple is for three-arg flags like --bind SRC DST or --ro-bind SRC DST.
func hasTriple(args []string, flag, a, b string) bool {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == flag && args[i+1] == a && args[i+2] == b {
			return true
		}
	}
	return false
}

func indexOfTriple(args []string, flag, a, b string) int {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == flag && args[i+1] == a && args[i+2] == b {
			return i
		}
	}
	return -1
}

func TestBwrapArgs_CoreIsolation(t *testing.T) {
	// Core invariants every run must enforce: namespaces unshared, env cleared,
	// HOME tmpfs'd, /etc from staged dir, project dir RW, chdir set.
	root, dirs := makeExistingDirs(t, "home/alice", "project", "etc-staged")
	home, project, etc := dirs[0], dirs[1], dirs[2]

	cfg := runConfig{
		ProjectDir: project,
		Home:       home,
		User:       "alice",
		Command:    []string{"/bin/true"},
		HostLayout: HostLayout{PathEnv: "/usr/bin:/bin"},
	}
	args := bwrapArgs(cfg, etc)

	mustContain := []string{
		"--unshare-user", "--unshare-ipc", "--unshare-pid",
		"--unshare-uts", "--unshare-cgroup",
		"--die-with-parent", "--new-session",
		"--clearenv",
	}
	for _, f := range mustContain {
		found := false
		for _, a := range args {
			if a == f {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing required isolation flag %q", f)
		}
	}

	if !hasFlagPair(args, "--tmpfs", home) {
		t.Errorf("HOME not tmpfs'd: --tmpfs %s missing from args", home)
	}
	if !hasTriple(args, "--ro-bind", etc, "/etc") {
		t.Errorf("staged /etc not bound: --ro-bind %s /etc missing", etc)
	}
	if !hasTriple(args, "--bind", project, project) {
		t.Errorf("project not RW-bound: --bind %s %s missing", project, project)
	}
	if !hasFlagPair(args, "--chdir", project) {
		t.Errorf("missing --chdir %s", project)
	}
	if !hasFlagPair(args, "--setenv", "HOME") {
		t.Errorf("missing --setenv HOME")
	}
	if !hasFlagPair(args, "--setenv", "USER") {
		t.Errorf("missing --setenv USER")
	}

	// Command is last
	if args[len(args)-1] != "/bin/true" {
		t.Errorf("command not appended last: got tail %v", args[len(args)-2:])
	}

	// Sanity: test tmpdir should not appear anywhere unexpected
	_ = root
}

func TestBwrapArgs_CredentialsNotLeaked(t *testing.T) {
	// The untrusted profile relies on HOME being tmpfs'd to hide ~/.ssh etc.
	// Assert: for a vanilla config (no Mounts, no ExtraRWMounts), nothing under
	// $HOME ends up bound into the sandbox. A regression that accidentally
	// bound $HOME itself would fail this.
	_, dirs := makeExistingDirs(t, "home/alice", "home/alice/.ssh", "home/alice/.aws", "project", "etc")
	home, ssh, aws, project, etc := dirs[0], dirs[1], dirs[2], dirs[3], dirs[4]

	cfg := runConfig{
		ProjectDir: project,
		Home:       home,
		User:       "alice",
		Command:    []string{"true"},
	}
	args := bwrapArgs(cfg, etc)

	for i, a := range args {
		// A bind of $HOME (or any subpath) would show up as the source arg of
		// --bind/--ro-bind. The tmpfs over $HOME is fine — that's the mechanism.
		if i > 0 && (args[i-1] == "--bind" || args[i-1] == "--ro-bind") {
			if a == home || strings.HasPrefix(a, home+"/") {
				if a == ssh || a == aws {
					t.Errorf("credential dir %s leaked into sandbox via %s", a, args[i-1])
				}
				// Also catch any accidental bind of $HOME itself
				if a == home {
					t.Errorf("$HOME itself was bind-mounted (%s) — breaks credential isolation", a)
				}
			}
		}
	}
}

func TestBwrapArgs_UserLocalBinPrependsPath(t *testing.T) {
	// When ~/.local/bin exists on the host, it gets prepended to PATH so
	// user-local agent installs resolve by name inside.
	root, _ := makeExistingDirs(t, "home/alice/.local/bin", "project", "etc")
	home := filepath.Join(root, "home/alice")
	project := filepath.Join(root, "project")
	etc := filepath.Join(root, "etc")

	cfg := runConfig{
		ProjectDir: project,
		Home:       home,
		User:       "alice",
		Command:    []string{"true"},
		HostLayout: HostLayout{PathEnv: "/usr/bin:/bin"},
	}
	args := bwrapArgs(cfg, etc)

	// Find --setenv PATH <value>
	var pathVal string
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--setenv" && args[i+1] == "PATH" {
			pathVal = args[i+2]
			break
		}
	}
	if pathVal == "" {
		t.Fatal("PATH not set in args")
	}
	wantPrefix := filepath.Join(home, ".local/bin") + ":"
	if !strings.HasPrefix(pathVal, wantPrefix) {
		t.Errorf("PATH = %q, want prefix %q", pathVal, wantPrefix)
	}
}

func TestBwrapArgs_UserLocalBinSkippedWhenMissing(t *testing.T) {
	// Negative of the above: without ~/.local/bin, PATH is just layout.PathEnv.
	_, dirs := makeExistingDirs(t, "home/alice", "project", "etc")
	home, project, etc := dirs[0], dirs[1], dirs[2]

	cfg := runConfig{
		ProjectDir: project,
		Home:       home,
		User:       "alice",
		Command:    []string{"true"},
		HostLayout: HostLayout{PathEnv: "/usr/bin:/bin"},
	}
	args := bwrapArgs(cfg, etc)

	var pathVal string
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--setenv" && args[i+1] == "PATH" {
			pathVal = args[i+2]
			break
		}
	}
	if pathVal != "/usr/bin:/bin" {
		t.Errorf("PATH = %q, want exactly layout PathEnv %q", pathVal, "/usr/bin:/bin")
	}
}

func TestBwrapArgs_ReadOnlyBinds(t *testing.T) {
	// layout.ReadOnlyBinds that exist get mounted RO identity-mapped.
	// Ones that don't exist are silently skipped (Stat fails).
	root, _ := makeExistingDirs(t, "home/alice", "project", "etc", "fakeusr", "fakebin")
	home := filepath.Join(root, "home/alice")
	project := filepath.Join(root, "project")
	etc := filepath.Join(root, "etc")
	usr := filepath.Join(root, "fakeusr")
	bin := filepath.Join(root, "fakebin")
	ghost := filepath.Join(root, "does-not-exist")

	cfg := runConfig{
		ProjectDir: project,
		Home:       home,
		User:       "alice",
		Command:    []string{"true"},
		HostLayout: HostLayout{ReadOnlyBinds: []string{usr, bin, ghost}},
	}
	args := bwrapArgs(cfg, etc)

	if !hasTriple(args, "--ro-bind", usr, usr) {
		t.Errorf("expected RO bind for %s", usr)
	}
	if !hasTriple(args, "--ro-bind", bin, bin) {
		t.Errorf("expected RO bind for %s", bin)
	}
	if hasTriple(args, "--ro-bind", ghost, ghost) {
		t.Errorf("ghost path %s should have been skipped", ghost)
	}
}

func TestBwrapArgs_AutoMountsBeforeProject(t *testing.T) {
	// bwrap is order-sensitive: if a caller invokes a binary from inside the
	// project dir, the auto-mount (RO) must come BEFORE --bind project (RW)
	// so the RW bind wins.
	_, dirs := makeExistingDirs(t, "home/alice", "project", "etc", "auto")
	home, project, etc, auto := dirs[0], dirs[1], dirs[2], dirs[3]

	cfg := runConfig{
		ProjectDir: project,
		Home:       home,
		User:       "alice",
		Command:    []string{"true"},
		AutoMounts: []string{auto},
	}
	args := bwrapArgs(cfg, etc)

	autoIdx := indexOfTriple(args, "--ro-bind", auto, auto)
	projIdx := indexOfTriple(args, "--bind", project, project)
	if autoIdx < 0 {
		t.Fatalf("auto-mount %s missing", auto)
	}
	if projIdx < 0 {
		t.Fatalf("project bind %s missing", project)
	}
	if autoIdx > projIdx {
		t.Errorf("auto-mount at %d comes after project bind at %d — RW would not shadow",
			autoIdx, projIdx)
	}
}

func TestBwrapArgs_AgentMountsRWTildeExpanded(t *testing.T) {
	// cfg.Mounts (from agent registry) are bound RW so the agent can refresh
	// tokens / persist state. "~/foo" paths expand against cfg.Home.
	root, _ := makeExistingDirs(t, "home/alice/.claude", "project", "etc")
	home := filepath.Join(root, "home/alice")
	project := filepath.Join(root, "project")
	etc := filepath.Join(root, "etc")
	claudeDir := filepath.Join(home, ".claude")

	cfg := runConfig{
		ProjectDir: project,
		Home:       home,
		User:       "alice",
		Command:    []string{"true"},
		Mounts:     []string{"~/.claude"},
	}
	args := bwrapArgs(cfg, etc)

	if !hasTriple(args, "--bind", claudeDir, claudeDir) {
		t.Errorf("expected RW bind for ~/.claude (expanded to %s)", claudeDir)
	}
}

func TestBwrapArgs_ExtraROvsRW(t *testing.T) {
	// --mount → RO, --mount-rw → RW. Paths that don't exist are skipped.
	_, dirs := makeExistingDirs(t, "home/alice", "project", "etc", "ro", "rw")
	home, project, etc, ro, rw := dirs[0], dirs[1], dirs[2], dirs[3], dirs[4]

	cfg := runConfig{
		ProjectDir:    project,
		Home:          home,
		User:          "alice",
		Command:       []string{"true"},
		ExtraROMounts: []string{ro, "/does/not/exist"},
		ExtraRWMounts: []string{rw, "/also/missing"},
	}
	args := bwrapArgs(cfg, etc)

	if !hasTriple(args, "--ro-bind", ro, ro) {
		t.Errorf("expected RO bind for %s", ro)
	}
	if !hasTriple(args, "--bind", rw, rw) {
		t.Errorf("expected RW bind for %s", rw)
	}
	if hasTriple(args, "--ro-bind", "/does/not/exist", "/does/not/exist") {
		t.Errorf("missing RO path should have been skipped")
	}
	if hasTriple(args, "--bind", "/also/missing", "/also/missing") {
		t.Errorf("missing RW path should have been skipped")
	}
}

func TestBwrapArgs_EnvForwarding(t *testing.T) {
	// Env vars that are set on the host get forwarded; unset ones are skipped.
	// (Values themselves are passed through; we only check plumbing.)
	_, dirs := makeExistingDirs(t, "home/alice", "project", "etc")
	home, project, etc := dirs[0], dirs[1], dirs[2]

	t.Setenv("AGENTPEN_TEST_SET", "hello")
	os.Unsetenv("AGENTPEN_TEST_UNSET")

	cfg := runConfig{
		ProjectDir: project,
		Home:       home,
		User:       "alice",
		Command:    []string{"true"},
		EnvVars:    []string{"AGENTPEN_TEST_SET", "AGENTPEN_TEST_UNSET"},
	}
	args := bwrapArgs(cfg, etc)

	// Must find --setenv AGENTPEN_TEST_SET hello
	found := false
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--setenv" && args[i+1] == "AGENTPEN_TEST_SET" && args[i+2] == "hello" {
			found = true
			break
		}
	}
	if !found {
		t.Error("AGENTPEN_TEST_SET=hello not forwarded")
	}

	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--setenv" && args[i+1] == "AGENTPEN_TEST_UNSET" {
			t.Error("AGENTPEN_TEST_UNSET forwarded despite being unset")
		}
	}
}

func TestStageEtc_HostsAndResolvConf(t *testing.T) {
	// stageEtc copies /etc/ (best-effort), then overwrites hosts/resolv.conf
	// with the sandbox-pinned versions.
	allowed := []string{"api.anthropic.com", "example.invalid"}
	ips := map[string]string{"api.anthropic.com": "10.0.0.5"}

	dir, err := stageEtc(allowed, ips)
	if err != nil {
		t.Fatalf("stageEtc: %v", err)
	}
	defer os.RemoveAll(dir)

	hosts, err := os.ReadFile(filepath.Join(dir, "hosts"))
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	got := string(hosts)
	if !strings.Contains(got, "127.0.0.1 localhost") {
		t.Errorf("hosts missing localhost entry:\n%s", got)
	}
	if !strings.Contains(got, "10.0.0.5 api.anthropic.com") {
		t.Errorf("hosts missing resolved entry:\n%s", got)
	}
	// Unresolved hosts are silently dropped — they simply don't appear.
	if strings.Contains(got, "example.invalid") {
		t.Errorf("hosts should not contain unresolved host:\n%s", got)
	}

	resolv, err := os.ReadFile(filepath.Join(dir, "resolv.conf"))
	if err != nil {
		t.Fatalf("read resolv.conf: %v", err)
	}
	if strings.TrimSpace(string(resolv)) == "" {
		t.Error("resolv.conf should be non-empty (commented stub)")
	}
}
