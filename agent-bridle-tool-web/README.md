# agent-bridle-tool-web

The capability-confined web tool group for agent-bridle: the `net` enforcer.
Its headline is `WebFetchTool`, a `web_fetch(url)` → structured-markdown tool
whose every request — and every redirect hop — is gated against the effective
`net` `Caveats`. Fetched bytes are data, never instructions: the result is the
structured envelope `{ url, final_url, status, title, markdown }`.

- Host allowlist, default-deny — the URL's host must satisfy the effective `net` scope
- SSRF block — DNS is resolved and private / loopback / link-local / unique-local addresses are rejected unless the host is explicitly allowlisted
- Per-redirect re-check — redirects are followed manually; every hop is re-screened before fetch
- DNS-rebinding pin — the connection is pinned to the exact IP that passed screening
- Budget honored — `max_calls` caps web fetches like any other tool

Heavy deps (`reqwest`+rustls, the readability extractor, the HTML→markdown
converter, the DNS resolver, tokio) live only here behind the `web` feature;
the crate compiles with `web` off (exposing nothing), so workspaces build
under `--no-default-features`.

Part of [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle),
the capability leash for agent tools — a shared, capability-governed tool
registry for the Gilamonster agent line.

## License

Apache-2.0
