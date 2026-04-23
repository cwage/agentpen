# Requirements

System-level dependencies for the `sandbox` wrapper. NixOS-focused; generalizes to other Linux via equivalent packages.

## Already installed (PR #33 + base NixOS)

| Tool | Purpose | Phase |
|---|---|---|
| `bubblewrap` (`bwrap` 0.11.0) | Core FS/exec/user/pid/mount namespace isolation | MVP |
| `iproute2` (`ip`, `nsenter`, `unshare`) | Netns creation, veth pairs, routing | MVP |
| `pasta` (from `passt`) | Userspace networking bridge for netns (rootless path, optional) | MVP or Phase 2 |
| `mitmproxy` / `mitmdump` | TLS termination, credential injection, content inspection | Phase 2 |
| `strace` | Syscall audit / seccomp policy development | MVP (dev) |
| `firejail` | Alternative sandboxing primitive; reference only | — |
| `nsjail` | Alternative sandboxing primitive; reference only | — |
| `podman` | Container isolation for `paranoid` profile | Paranoid |
| `podman-compose` | Container orchestration (from PR #33) | Paranoid |
| `getent`, `host` | DNS resolution at wrapper startup | MVP |
| `claude`, `codex` | Target agent binaries | — |

## Missing — need to add

| Tool | Purpose | Phase | Nix attribute |
|---|---|---|---|
| `nftables` (`nft`) | In-netns IP allowlist firewall rules | MVP | `nftables` |
| `slirp4netns` | Optional fallback for rootless netns egress (alternative to pasta) | MVP (maybe) | `slirp4netns` |
| `libseccomp` / `seccomp-tools` | Seccomp BPF filter construction | MVP (soon) | `libseccomp`, `seccomp-tools` |

`nftables` is blocking Phase B (network filtering). The others can be added as needed.

## Runtime/elevation requirements

- **Root or setuid** for netns creation with `ip netns add`, veth pair creation, and loading nftables rules into the netns. MVP uses `sudo`. Later packaging: setuid helper, `CAP_NET_ADMIN` file capability, or a systemd socket-activated helper service.
- Rootless user namespaces: already enabled on NixOS by default (required for `bwrap`).
- Rootless podman: enabled via PR #33 (needed only for `paranoid`).

## Out of scope for MVP

- `mitmproxy` CA cert generation/trust injection (Phase 2).
- Container runtime wiring for `paranoid` (Phase 2+).
- Credential store / proxy-side key management (Phase 2).
