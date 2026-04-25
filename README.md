# agentpen

Confinement wrapper for LLM coding agents (Claude Code, Codex, Aider, OpenCode) on Linux. Flips the default from `--dangerously-skip-permissions` to "confined by default": clone a third-party repo and run an agent on it without worrying about prompt-injection → credential theft or persistent compromise.

## Status

MVP, Linux **x86_64 only** (the seccomp BPF filter is currently amd64-specific; arm64 is [tracked as a follow-up](https://github.com/cwage/agentpen/issues/10)). Single profile shipping (`untrusted`, default); `paranoid` stubbed. Auto-detects NixOS vs FHS layouts, so the same binary works on NixOS and Ubuntu/Debian/etc.

## What the untrusted profile blocks

- **Filesystem**: `$HOME` becomes a fresh tmpfs; only the project directory is writable; credentials (`~/.ssh`, `~/.aws`, `~/.gnupg`) and sibling repos are invisible.
- **Network**: pasta-managed userns + a /32 route to the gateway → no default route, no kernel-level reachability outside the proxy. The agent's `/etc/hosts` maps allowed hostnames to an in-namespace forwarder, which splices to an SNI-sniffing TCP proxy on host loopback that gates outbound by hostname (no TLS termination, no MITM). Direct-IP egress is rejected by the kernel.
- **Env**: scrubbed, with per-agent passthrough only (no `SSH_AUTH_SOCK`, no arbitrary host env).
- **Seccomp** (amd64): BPF filter blocking `ptrace`, `keyctl` family, `mount`/`pivot_root`, `bpf`, kernel module syscalls, `reboot`/`kexec`, and other kernel-touching vectors.

Rootless: no `sudo`, no `setcap`, no sysctl tweaks, no persistent host state. The whole sandbox tears down with the process.

Known limitation: a misbehaving agent can SIGKILL the in-namespace forwarder and lose its own outbound until the next `agentpen` invocation. Self-DoS, no privilege escalation — see `notes.md`.

Not defended against: steganographic exfil inside prompt bodies (a fundamental limit); a malicious agent binary stealing the API credential still in-sandbox (phase 2 work, see `notes.md`).

## Requirements

Runtime: `bubblewrap`, `passt` (provides `pasta`), `iproute2`, and a Linux kernel with user namespaces enabled.

Run `agentpen --check` to report which layers this host can actually enforce.

## Build

With Nix (recommended, no host pollution):

    nix develop --command go build .

With Docker (works anywhere `docker compose` does, pins the Go toolchain):

    UID=$(id -u) GID=$(id -g) docker compose run --rm build

(The explicit `UID`/`GID` ensure the output binary is owned by you. Bash doesn't export them by default, so `compose.yml`'s `${UID:-1000}` substitution would otherwise silently fall back to `1000:1000`.)

With system Go 1.21 or newer (the `go 1.26.1` directive in `go.mod` auto-downloads the matching toolchain on first build):

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

## License

MIT. See [`LICENSE`](./LICENSE).
