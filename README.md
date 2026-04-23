# agentpen

Confinement wrapper for LLM coding agents (Claude Code, Codex, Aider, OpenCode) on Linux. Flips the default from `--dangerously-skip-permissions` to "confined by default": clone a third-party repo and run an agent on it without worrying about prompt-injection → credential theft or persistent compromise.

## Status

MVP, Linux only. Single profile shipping (`untrusted`, default). `paranoid` stubbed. Auto-detects NixOS vs FHS layouts, so the same binary works on NixOS and Ubuntu/Debian/etc.

## What the untrusted profile blocks

- **Filesystem**: `$HOME` becomes a fresh tmpfs; only the project directory is writable; credentials (`~/.ssh`, `~/.aws`, `~/.gnupg`) and sibling repos are invisible.
- **Network**: netns + nftables allowlist — only the agent's API endpoints reachable; DNS pinned to `/etc/hosts`; everything else drops.
- **Env**: scrubbed, with per-agent passthrough only (no `SSH_AUTH_SOCK`, no arbitrary host env).
- **Seccomp** (amd64): BPF filter blocking `ptrace`, `keyctl` family, `mount`/`pivot_root`, `bpf`, kernel module syscalls, `reboot`/`kexec`, and other kernel-touching vectors.

Not defended against: steganographic exfil inside prompt bodies (a fundamental limit); a malicious agent binary stealing the API credential still in-sandbox (phase 2 work, see `notes.md`).

## Requirements

Runtime: `bubblewrap`, `nftables`, `iproute2`, `iptables`, `sudo`, `runuser`, and a Linux kernel with user namespaces enabled.

Run `agentpen --check` to report which layers this host can actually enforce.

## Build

With Nix (recommended, no host pollution):

    nix develop --command go build .

With system Go:

    go build .

Produces `./agentpen`.

## Usage

    agentpen claude                       # run claude confined
    agentpen codex                        # same for codex
    agentpen --check                      # host capability report
    agentpen --allow example.com claude   # add to allowlist

Known agents auto-detected from the command's basename: `claude`, `codex`, `aider`, `opencode`. Override with `--agent NAME`. See `agentpen --help` for all flags.

## Design notes

See [`notes.md`](./notes.md) for the threat model, design decisions, and deferred work.
