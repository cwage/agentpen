package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Populated at build time via -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
// Defaults identify unreleased local builds.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type runConfig struct {
	Profile       string
	Agent         string
	ProjectDir    string
	Home          string
	User          string
	AllowedHosts  []string
	EnvVars       []string
	Mounts        []string
	ExtraROMounts []string
	ExtraRWMounts []string
	AutoMounts    []string
	Command       []string
	HostLayout    HostLayout
}

func usage() {
	known := knownAgents()
	sort.Strings(known)
	fmt.Fprintf(os.Stderr, `usage: agentpen [options] [--] <command> [args...]
       agentpen --check

Runs <command> inside a confined sandbox (pasta + bwrap + seccomp) with an
SNI-gated network egress proxy on host loopback. No sudo, no setcap, no
persistent host state.

options:
  --profile P      profile: untrusted (default), paranoid (not yet implemented)
  --agent NAME     override detected agent (default: basename of command)
  --allow HOST     add hostname to network allowlist (repeatable)
  --env VAR        forward env var if set on host (repeatable)
  --mount PATH     extra read-only bind mount (repeatable)
  --mount-rw PATH  extra read-write bind mount (repeatable)
  --project DIR    project dir, bound RW (default: $PWD)
  --check          report which sandbox layers this host can enforce and exit
  --version        print version and exit
  -h, --help       show this help

known agents: %s
`, strings.Join(known, " "))
}

func main() {
	// Internal subcommands run when agentpen re-execs itself inside pasta's
	// userns. Dispatched before flag parsing so the inner argv shape can be
	// independent of the user-facing CLI.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "__sandbox-init":
			if err := runSandboxInit(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "agentpen __sandbox-init:", err)
				os.Exit(1)
			}
			return
		case "__forwarder":
			if err := runForwarder(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "agentpen __forwarder:", err)
				os.Exit(1)
			}
			return
		}
	}

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agentpen:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		profile    string
		agent      string
		projectDir string
		allow      stringList
		env        stringList
		mountRO    stringList
		mountRW    stringList
		check      bool
		showVer    bool
	)

	fs := flag.NewFlagSet("agentpen", flag.ContinueOnError)
	fs.Usage = usage
	fs.StringVar(&profile, "profile", "untrusted", "")
	fs.StringVar(&agent, "agent", "", "")
	fs.StringVar(&projectDir, "project", "", "")
	fs.Var(&allow, "allow", "")
	fs.Var(&env, "env", "")
	fs.Var(&mountRO, "mount", "")
	fs.Var(&mountRW, "mount-rw", "")
	fs.BoolVar(&check, "check", false, "")
	fs.BoolVar(&showVer, "version", false, "")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		return err
	}

	if showVer {
		fmt.Printf("agentpen %s (commit %s, built %s)\n", version, commit, date)
		return nil
	}

	if check {
		fmt.Printf("agentpen %s\n\n", version)
		fmt.Print(detectCapabilities().Report(profile))
		return nil
	}

	command := fs.Args()
	if len(command) == 0 {
		usage()
		os.Exit(2)
	}

	switch profile {
	case "untrusted":
	case "paranoid":
		return fmt.Errorf("paranoid profile not yet implemented")
	default:
		return fmt.Errorf("unknown profile: %s", profile)
	}

	caps := detectCapabilities()
	if err := caps.ValidateFor(profile); err != nil {
		return fmt.Errorf("%w\nrun 'agentpen --check' for details", err)
	}

	// Agent inference
	if agent == "" {
		if _, ok := agents[filepath.Base(command[0])]; ok {
			agent = filepath.Base(command[0])
		}
	}
	if agent != "" {
		if _, ok := agents[agent]; !ok {
			return fmt.Errorf("unknown agent %q (known: %s)", agent, strings.Join(knownAgents(), " "))
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("LOGNAME")
	}

	if projectDir == "" {
		projectDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("getwd: %w", err)
		}
	}
	projectDir, err = filepath.Abs(projectDir)
	if err != nil {
		return err
	}
	if info, err := os.Stat(projectDir); err != nil || !info.IsDir() {
		return fmt.Errorf("project dir not found: %s", projectDir)
	}
	if projectDir == home || projectDir == "/" {
		return fmt.Errorf("refusing to use %s as project dir", projectDir)
	}

	// Resolve the agent binary on the host before the sandbox starts: follow
	// symlinks and collect any dirs that need to be bound so the binary stays
	// reachable inside (user-local installs like ~/.local/bin/claude → ~/.local/share/...
	// would otherwise vanish with the tmpfs'd $HOME).
	layout := detectHostLayout()
	resolvedCmd, autoMounts, err := resolveCommand(command, layout)
	if err != nil {
		return err
	}

	cfg := runConfig{
		Profile:       profile,
		Agent:         agent,
		ProjectDir:    projectDir,
		Home:          home,
		User:          user,
		Command:       resolvedCmd,
		HostLayout:    layout,
		ExtraROMounts: mountRO,
		ExtraRWMounts: mountRW,
		AutoMounts:    autoMounts,
	}
	if agent != "" {
		a := agents[agent]
		cfg.AllowedHosts = append(cfg.AllowedHosts, a.AllowedHosts...)
		cfg.EnvVars = append(cfg.EnvVars, a.EnvVars...)
		cfg.Mounts = append(cfg.Mounts, a.Mounts...)
	}
	cfg.AllowedHosts = dedupe(append(cfg.AllowedHosts, allow...))
	cfg.EnvVars = dedupe(append(cfg.EnvVars, env...))

	// Stage /etc: each allowed hostname → 127.0.0.1 (the in-namespace forwarder).
	etcDir, err := stageEtc(cfg.AllowedHosts)
	if err != nil {
		return fmt.Errorf("stage /etc: %w", err)
	}
	defer os.RemoveAll(etcDir)

	// Build bwrap argv. Seccomp filter goes via FD 3 — we wrap the final exec
	// in a bash snippet inside __sandbox-init that reopens the file as FD 3
	// before exec'ing bwrap. (Same pattern as before, sans the sudo+runuser layer.)
	bwrapArgv := bwrapArgs(cfg, etcDir)

	filterPath, err := writeSeccompFilter()
	if err != nil {
		return fmt.Errorf("seccomp filter: %w", err)
	}
	defer os.Remove(filterPath)

	// Prepend --seccomp 3 to the bwrap args.
	bwrapArgv = append([]string{"--seccomp", "3"}, bwrapArgv...)

	// Rewrite to: bash -c 'exec bwrap "$@" 3<"$0"' FILTER_PATH BWRAP_ARGS...
	// __sandbox-init exec's this bash snippet which opens FD 3 and finally exec's bwrap.
	bashSnippet := `exec bwrap "$@" 3<"$0"`
	wrappedBwrap := append([]string{"bash", "-c", bashSnippet, filterPath}, bwrapArgv...)

	// Start SNI proxy on host loopback.
	proxy, err := startSNIProxy(cfg.AllowedHosts, func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	})
	if err != nil {
		return err
	}
	defer proxy.Close()

	// Launch pasta -> __sandbox-init -> bash -> bwrap -> user command.
	code, err := runPasta(proxy.Port(), wrappedBwrap)
	if err != nil {
		return err
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
