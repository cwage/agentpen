package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
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
       agentpen --reap

Runs <command> inside a confined sandbox (bwrap + netns + nftables + seccomp).

options:
  --profile P      profile: untrusted (default), paranoid (not yet implemented)
  --agent NAME     override detected agent (default: basename of command)
  --allow HOST     add hostname to network allowlist (repeatable)
  --env VAR        forward env var if set on host (repeatable)
  --mount PATH     extra read-only bind mount (repeatable)
  --mount-rw PATH  extra read-write bind mount (repeatable)
  --project DIR    project dir, bound RW (default: $PWD)
  --check          report which sandbox layers this host can enforce and exit
  --reap           tear down leaked ap-* netns from crashed/killed prior runs
  -h, --help       show this help

known agents: %s
`, strings.Join(known, " "))
}

func main() {
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
		reap       bool
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
	fs.BoolVar(&reap, "reap", false, "")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		return err
	}

	// --check: report capabilities and exit without running anything
	if check {
		fmt.Print(detectCapabilities().Report(profile))
		return nil
	}

	// --reap: tear down leaked namespaces from prior crashed/killed runs
	if reap {
		if err := sudoRun("-v"); err != nil {
			return fmt.Errorf("sudo: %w", err)
		}
		reaped, err := reapOrphans()
		if err != nil {
			return err
		}
		if len(reaped) == 0 {
			fmt.Println("no orphaned agentpen namespaces found")
		} else {
			fmt.Printf("reaped %d orphan(s): %s\n", len(reaped), strings.Join(reaped, " "))
		}
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

	// Validate capabilities up front (fail-closed).
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

	// Merge registry + user-supplied
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

	// Resolve hosts
	allowedIPs, err := resolveHosts(cfg.AllowedHosts)
	if err != nil {
		return err
	}
	if len(cfg.AllowedHosts) > 0 && len(allowedIPs) == 0 {
		return fmt.Errorf("couldn't resolve any allowed hosts")
	}

	// Acquire sudo upfront so we don't prompt mid-setup
	if err := sudoRun("-v"); err != nil {
		return fmt.Errorf("sudo: %w", err)
	}

	// Auto-reap orphans from crashed/killed prior runs. Surface listing errors
	// as warnings but proceed — a failed reap shouldn't block a new run.
	if reaped, err := reapOrphans(); err != nil {
		fmt.Fprintf(os.Stderr, "agentpen: auto-reap skipped: %v\n", err)
	} else if len(reaped) > 0 {
		fmt.Fprintf(os.Stderr, "agentpen: reaped %d leaked namespace(s): %s\n",
			len(reaped), strings.Join(reaped, " "))
	}

	// Netns setup
	ns := newNetns(os.Getpid())
	cleanup := func() {
		_ = ns.teardown()
	}
	defer cleanup()
	// Also clean on signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cleanup()
		os.Exit(130)
	}()

	if err := ns.setup(allowedIPs); err != nil {
		return err
	}

	// Stage /etc
	etcDir, err := stageEtc(cfg.AllowedHosts, firstIPFor(cfg.AllowedHosts))
	if err != nil {
		return fmt.Errorf("stage /etc: %w", err)
	}
	defer os.RemoveAll(etcDir)

	// Build bwrap argv
	args := bwrapArgs(cfg, etcDir)

	// Write seccomp filter to a tempfile; pass via FD 3 to bwrap.
	// sudo drops inherited FDs, so we wrap the final exec in a bash snippet
	// that reopens the file as FD 3 inside the sudo-launched shell.
	filterPath, err := writeSeccompFilter()
	if err != nil {
		return fmt.Errorf("seccomp filter: %w", err)
	}
	defer os.Remove(filterPath)

	// Prepend --seccomp 3 to the bwrap args (before the command to run)
	args = append([]string{"--seccomp", "3"}, args...)

	// bash -c '... exec bwrap ARGS 3<FILTER_PATH' FILTER_PATH ARGS...
	bashSnippet := `exec bwrap "$@" 3<"$0"`
	fullArgs := append([]string{
		"ip", "netns", "exec", ns.Name,
		"runuser", "-u", user, "--",
		"bash", "-c", bashSnippet, filterPath,
	}, args...)

	cmd := exec.Command("sudo", fullArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Preserve exit code from the inner command when possible
		if exit, ok := err.(*exec.ExitError); ok {
			os.Exit(exit.ExitCode())
		}
		return err
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
