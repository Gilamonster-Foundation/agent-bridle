# Security Policy

`agent-bridle` is the capability-enforcement **leash** for agent tools: a tool can
act only through a `ToolContext` minted inside `Gate::authorize`, and receives the
*meet* of granted-and-required authority (least authority by construction). Because
it is a security boundary, correctness and privacy are enforced in CI.

## Reporting a vulnerability

Open a private security advisory on this repository (GitHub → Security → Report a
vulnerability), or contact the maintainers out-of-band. Please do **not** file
public issues for undisclosed vulnerabilities.

## Public-repository privacy rules (enforced)

This repo is public. It must never contain the operational specifics of any real
deployment or workstation. The following are **prohibited in code, docs, tests,
fixtures, comments, and commit messages**:

- Real hostnames, private IP addresses (RFC1918 / CGNAT), internal domains/DNS
  names, or overlay-network (mesh / tailnet) names.
- Real usernames, home paths (`/home/<user>`), personal email addresses, or
  directory realms.
- Any secret: passwords, API keys, tokens, OAuth client secrets, private keys,
  certificate private halves, or signing seeds.

> **Note on the net enforcer.** `agent-bridle-tool-web` is the SSRF/`net` enforcer,
> so it legitimately *names* the private ranges it blocks (`10.0.0.0/8`,
> `192.168.0.0/16`, `169.254.169.254`, …). Those generic range identifiers are
> allowlisted; a real operational *host* (a non-zero host part) is still caught.

Use **placeholders only**: `example.com` / `example.lan`, `192.0.2.0/24`
(TEST-NET-1), `198.51.100.0/24`, `203.0.113.0/24`, `user@example.com`.

## Enforcement

- **`security-audit` CI** (`.github/workflows/security-audit.yml`): a gitleaks
  secret scan + the internal-specifics linter
  (`scripts/check-internal-specifics.sh`). A finding **blocks the merge**.
- **Pre-commit** (`.pre-commit-config.yaml`): the same two checks run locally
  before a commit is created — see `docs/PRIVACY.md`.

## Secret handling in code

- Secrets are never committed, never logged, and never written to durable disk.
- The step-up verifier (`Ed25519Verifier`) only ever consumes *public* verifying
  keys + assertions; the only keys in the tree are fixed, non-secret **test**
  seeds (literal `[N u8; 32]` arrays in `step_up.rs`).
