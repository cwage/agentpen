# Sandboxing LLM coding agents — working notes

Notes-only directory, not a repo. Tracks the design conversation before we start building.

## Goal

Flip the default posture for running LLM coding agents (Claude Code, codex, opencode) from "YOLO with `--dangerously-skip-permissions`" to "confined by default when the code isn't trusted." Specifically, make it safe to clone a third-party repo and run an agent on it without worrying about prompt-injection → credential exfiltration / persistent compromise.

Target machine: `thinkpad` (NixOS). Design should generalize to plain Linux; macOS is a possible future port.

## Threat model

Two attacker classes. Both assumed realistic; the design must address both.

**Class A — Prompt injection.** Attacker controls content the agent reads: source files, READMEs, `.claude/` configs, filenames, build output, tool-use results. Goal: coerce the model into:

1. Exfiltrating secrets (`~/.ssh/`, `~/.aws/`, `~/.gnupg/`, browser profiles, env vars including the LLM API key) via network requests or encoded output.
2. Persistent compromise — writes to `~/.bashrc`, crontabs, systemd units, other dotfiles.
3. Lateral movement — sibling repos, local services, other credentials.

**Class B — Supply-chain compromise.** The agent binary (Claude Code, codex CLI, etc.) or the model behind it is treated as potentially adversarial. LLM vendors are uniquely-targeted supply chains right now: high-value data flows through them, state actors and criminals both motivated, npm distribution channel is soft.

**Implication for design:** every guarantee we rely on must be enforced *outside* the agent binary, by the kernel and network stack. `/sandbox` and any other in-binary defense is "bonus if Anthropic ships it correctly," never load-bearing.

## What's done

- **PR #33 merged** into `nix-workstation`: adds `bubblewrap`, `firejail`, `nsjail`, `podman-compose`, `mitmproxy`, `strace`, and enables rootless podman alongside rootless docker. Gives us the primitive toolkit.

## UX direction (decided)

- **Profile-based wrapper**, not flag-per-layer as the primary interface. Flags override individual layers for debugging/iteration.
- **Profiles**: `untrusted` (default), `paranoid`. (`trusted` dropped for now; revisit if a concrete ergonomic need emerges.)
- **`--audit` modifier** applies to any profile: runs the profile's checks permissively and logs what *would* have been blocked. Makes tuning tractable without breaking workflows.
- **Separate repo** (outside `nix-workstation`) for the wrapper. Reasons: publishable, reusable beyond NixOS, own dev/test cycle. Wires back into `nix-workstation` later via a flake input or overlay. Name TBD.

## Profile sketch (MVP — proxy deferred, see below)

| Layer | `untrusted` (default) | `paranoid` |
|---|---|---|
| Filesystem | project RW; `$HOME` → empty tmpfs; only `/nix/store` readable beyond | untrusted + ephemeral overlay (writes disposable, promoted explicitly) |
| Network | netns + allowlist: LLM API host only (registries handled outside the sandbox) | same + SNI-level enforcement |
| Credentials | passed through (env or mounted file) — MVP compromise; see scope note | same |
| Env / agents | scrubbed env; no SSH/GPG agent forwarding | same |
| API channel inspection | none (phase 2, requires proxy) | none (phase 2, requires proxy) |
| seccomp | tight | tight + full syscall audit |
| Resource caps | wall-clock only | cgroup wall-clock + CPU + memory + bandwidth |
| Isolation | namespaces + seccomp | + podman or microVM |

## MVP scope note

Proxy-injected credentials, TLS termination, content inspection, and byte-budget tracking are deferred to a phase-2 effort. They introduce significant architectural questions (where the proxy runs, cert trust, netns routing, credential store) that trade poorly against the goal of getting a playable wrapper quickly.

Accepted compromise: in the MVP the sandbox holds the real agent credential (env var or mounted file from `~/.claude/` etc.), so a subverted agent binary could exfil it via its one allowed channel. Conscious trade:
- The credential is usable for LLM spend and, for OAuth session tokens, potentially some Anthropic-console identity scope. Rotatable in all cases.
- Class A (prompt injection) defense — the primary goal — is unaffected.
- Steganographic exfil through the API channel was already outside what we can defend against even with the proxy.

Phase 2 adds back: mitmproxy-based TLS termination, out-of-sandbox credential injection, and (paranoid-only) content inspection + byte budgets.

## Defense ordering

Layered so failure of any one doesn't collapse the rest. All enforced *outside* the agent binary.

**MVP:**

1. **Filesystem denial.** If `~/.ssh` isn't in the sandbox, no exfiltration path exists regardless of what the agent or binary tries. bwrap, outside the binary.
2. **Network allowlist.** Netns + IP/SNI allowlist blocks exfiltration to arbitrary endpoints. Outside the binary.
3. **Env scrub + no agent forwarding.** Strips SSH_AUTH_SOCK, GPG agent sockets, arbitrary env vars; binary sees only what we pass.
4. **Ephemeral FS overlay + cgroup resource caps.** Blast-radius containment. Paranoid-only.

**Phase 2 (proxy work):**

5. **Proxy-injected API credentials.** The binary never holds the real key. Proxy terminates TLS, adds `x-api-key` on the way out. Closes the credential-dump vector against a malicious binary.
6. **Content inspection + byte budget on the API channel.** Paranoid-only. Catches header patterns, caps slow-exfil bandwidth.

## What we can't defend against, even with all of this

- **Steganographic exfil inside otherwise-legitimate prompts.** A subverted model encodes data into bytes that look like normal code context. Pattern-matching catches headers, not semantics.
- **Model-level subversion.** If the model is trained to leak, we can't detect it from outside. Fundamental limit.
- **Timing / slow-bit exfil across many calls.** Below the byte budget, across many sessions, an attacker can get data out one bit at a time.

The practical boundary: fully defended against bulk exfil, credential dumping, persistent compromise, and arbitrary network use. Partially defended against steganographic exfil (budget bounds volume, not existence). Not defended against a compromised model.

## Existing landscape (research summary)

- **Claude Code has a built-in `/sandbox`** — bubblewrap + UDS-proxy for network, documented. **Caveats:** closed source (obfuscated JS bundle), escapable via `/proc/self/root/usr/bin/npx` (Ona, March 2026), updated silently. Useful bonus layer, never load-bearing for us.
- **Codex CLI** ships Landlock + seccomp sandbox. Strong reference for seccomp policy; same trust caveats as Claude.
- **Aider, opencode** — no native sandbox; permission prompts only.
- **tomeon/bubbLLMwrap** — Nix + bwrap + per-language profiles. Closest structural match. Possible skeleton; still has to be read for trustworthiness before adoption.
- **CaptainMcCrank/SandboxedClaudeCode** — 22 stars, bwrap/firejail/container backends. No profiles, no proxy-auth. Reference for seccomp policy and firejail profiles.
- **Formal.ai blog + proxyclawd** — proxy-injected-auth pattern exists as a recipe/blog post, never packaged as a reusable component. This is the novel contribution worth publishing.

## Revised approach (decided)

Outer layers are the primary defense, not defense-in-depth. `/sandbox` is a bonus if it works, never relied on.

**MVP:**

1. **bwrap + seccomp outside the binary** as the FS/exec boundary. We own it; we can reason about it.
2. **Network namespace + IP/SNI allowlist** for network (no proxy yet). LLM API host only.
3. **Profile layer** drives which outer layers activate. Default `untrusted`; `paranoid` tightens.
4. **Seccomp policy** — steal from Codex CLI as a reference point; re-verify before trusting.
5. **Fork bubbLLMwrap skeleton** if its bwrap policy survives audit; otherwise write our own.
6. **`/sandbox`** — optionally invoke when running Claude Code, purely as an extra layer Anthropic maintains. If it breaks or is escaped, our outer layers still hold.

**Phase 2:** mitmproxy + credential-injecting addon; paranoid adds body inspection and byte budget.

## Decided

- No `trusted` profile for now. Default is `untrusted`; `paranoid` is explicit opt-in.
- `untrusted` network allowlist: LLM API host only. Registry installs happen outside the sandbox.
- Proxy (TLS termination, credential injection, content inspection) deferred to phase 2.
- Network filtering: netns + nftables IP allowlist, resolved from hostname at wrapper startup. Upgrade to DNS+ipset or SNI proxy if CDN rotation proves flaky.
- Agent-aware endpoints + credentials: built-in per-agent registry (allowed hosts, env-var passthrough list, config mount paths). `claude` registry entry must include `api.anthropic.com`, `platform.claude.com`, `console.anthropic.com`, and mount both `~/.claude/` and `~/.claude.json`.
- Agent config mounts are RW in MVP (agents need to refresh OAuth tokens / persist state). Moves back to RO in phase 2 once the proxy handles credentials externally.
- Tool name: `sandbox` as a working name; rename later.
- Language: Go (rewrite decided after bash MVP was proven end-to-end). Single binary for the rewrite; privileged-helper split is its own later milestone.
- Build: no Docker. Use `nix shell nixpkgs#go gopls` ad-hoc for dev; a `flake.nix` later if the build step grows. GitHub Actions will use `actions/setup-go` when we publish, not Docker.
- Cross-distro portability: the real work is parameterizing FS bind mounts for non-NixOS (FHS layout detection), not the build system. Bake into the Go rewrite from the start.

## Deferred: graceful degradation + capability reporting

Not yet implemented. Capturing now so future code stays refactor-friendly.

**Principle:** fail-closed by default. The whole project's pitch is "flip the default from YOLO to safe." Silently weakening protections on a misconfigured host recreates the problem. Any degraded mode must be explicit opt-in.

**Tiers:**
- *Must-have floor:* bwrap + user namespaces. Missing ⇒ refuse to run (no meaningful sandbox without these).
- *Degradable layers:* network filter (nft preferred, iptables fallback, neither available ⇒ offline-only or explicit opt-out), seccomp (optional), cgroup caps (optional).

**Surface to build:**
- `sandbox --check` (or similar) — capability report: for the current host, enumerate which layers are available and which would be enforced. Small feature, high clarity value. Good onboarding / CI / debugging aid.
- `--best-effort` (or similar) flag — explicit opt-in to run with fewer protections than the profile requests. Prints a loud warning summarizing what's off. Without it, missing layers cause a refuse-to-run error with install hints.

**Design constraint for the current code:** keep "detect capability" and "apply layer" factored out so each layer can be toggled independently. The current Go code has netns setup hardcoded into `main.run()`; before we add seccomp or cgroup layers, refactor so the orchestration looks like a pipeline of layer-appliers driven by a capabilities struct. Avoid threading individual booleans through the call chain.

## MVP status

End-to-end proven: `sandbox claude` in a clean repo successfully confines claude, blocks SSH/AWS/sibling-repo reads, allows Anthropic endpoints. Implementation is Go, built via `nix develop --command go build .`, output at `./sandbox`.

Files: `main.go` (CLI), `agents.go` (registry), `host.go` (NixOS/FHS layout detection), `network.go` (netns/veth/nft), `fs.go` (/etc staging + bwrap argv), `flake.nix` (dev shell).

## References

- Claude Code sandboxing: https://code.claude.com/docs/en/sandboxing
- Anthropic engineering post: https://www.anthropic.com/engineering/claude-code-sandboxing
- Ona escape writeup: https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox
- Codex Linux sandbox: https://github.com/openai/codex/tree/main/codex-rs/linux-sandbox
- tomeon/bubbLLMwrap: https://github.com/tomeon/bubbLLMwrap
- CaptainMcCrank/SandboxedClaudeCode: https://github.com/CaptainMcCrank/SandboxedClaudeCode
- rivet-dev/sandbox-agent: https://github.com/rivet-dev/sandbox-agent
- opencode sandbox issue: https://github.com/sst/opencode/issues/2242
- Formal.ai proxy writeup: https://www.formal.ai/blog/using-proxies-claude-code/
- patrickmccanna.net: https://patrickmccanna.net/a-better-way-to-limit-claude-code-and-other-coding-agents-access-to-secrets/
- dyshay/proxyclawd: https://github.com/dyshay/proxyclawd
