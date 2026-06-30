# Privacy & the public/private split

`agent-bridle` is **public** software. A public repo that leaks the operational
specifics of the maintainer's environment (real hostnames, private addresses, home
paths, accounts) hands an attacker a map. This document defines the boundary and
how it is enforced.

## The rule

- **Public (this repo):** generic, reusable code and documentation. Every example
  uses a **placeholder**, never a real value.
- **Private (operator-controlled):** the actual environment — real hostnames,
  addresses, accounts, paths — never flows here.
- **Direction of authorship:** public docs are authored **placeholder-first**.
  Never copy-paste a real value from a private note into this repo.

## Approved placeholders

| Category | Use this | Never this |
|---|---|---|
| Host / domain | `example.com`, `example.lan`, `host.example.lan` | your real hostnames |
| IP / CIDR | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737 TEST-NET) | real RFC1918 / CGNAT host addresses |
| Overlay network | `<OVERLAY-NETWORK>` | your real mesh / tailnet name |
| User / email | `user@example.com`, `alice`, `bob` | real people / personal email providers |
| Path | `/path/to/workspace` | your real `/home/<user>/…` |

## Forbidden categories (blocked by CI)

Real values in any of these must never appear in code, docs, tests, fixtures,
comments, or commit messages:

1. Hostnames, private/CGNAT IP **hosts**, internal DNS names, overlay-network names.
2. Usernames, home paths, email addresses, directory realms.
3. Any secret material (passwords, API keys, tokens, private keys, signing seeds).

### Legitimate exception: the net enforcer

`agent-bridle-tool-web` blocks SSRF by **enumerating** the private ranges
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`,
`169.254.169.254`, …). Those generic **range bases** are allowlisted by the
linter, and `agent-bridle-tool-web/src/net_guard.rs` (the deny-list source) is
excluded — but the patterns still catch a real host with a non-zero host part.

## Enforcement

- **CI** (`.github/workflows/security-audit.yml`): gitleaks (secret scan) + the
  internal-specifics linter (`scripts/check-internal-specifics.sh`, generic
  pattern set) run on every push and pull request. A finding blocks the merge.
- **Local** (`.pre-commit-config.yaml`): the same checks run before a commit is
  created, so leaks are caught before they leave a workstation.

## If CI flags you

Replace the flagged value with the appropriate placeholder from the table above
and re-push. If you believe it is a false positive on a genuine documentation
example, prefer switching the example to RFC 5737 / `example.*` ranges rather than
widening the linter.
