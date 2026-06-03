//! `agent-bridle-tool-web` — the capability-confined web tool group.
//!
//! This crate exercises the **`net`** axis of the leash (DESIGN §7): the axis
//! no other tool touches. Its headline is [`WebFetchTool`], a `web_fetch(url)`
//! → structured-markdown tool whose every request — and every redirect hop — is
//! gated against the effective `net` [`Caveats`](agent_bridle_core::Caveats):
//!
//! 1. **Host allowlist, default-deny.** The URL's host must satisfy the
//!    effective `net` scope ([`ToolContext::check_net`](agent_bridle_core::ToolContext::check_net)).
//! 2. **SSRF block.** The host's DNS is resolved and any private / loopback /
//!    link-local / unique-local address is **rejected** — *unless* that host is
//!    explicitly named in the `net` allowlist (so a test or a deliberately-named
//!    internal endpoint can be opted in).
//! 3. **Per-redirect re-check.** Redirects are followed *manually*: every hop's
//!    host is re-screened by (1) and (2) before it is fetched — a 302 to a
//!    disallowed or private host is denied, never blindly followed.
//! 4. **DNS-rebinding pin.** The connection is pinned to the exact IP that
//!    passed screening (`reqwest`'s `resolve_to_addrs`), so a rebind between the
//!    check and the connect cannot smuggle traffic to a different address.
//! 5. **Budget / generation.** Honored by the gate at dispatch (the leash
//!    minted the [`ToolContext`](agent_bridle_core::ToolContext) this tool runs
//!    under), so a `max_calls` bound caps web fetches like any other tool.
//!
//! Fetched bytes are **data, never instructions**: the result is the structured
//! envelope `{ url, final_url, status, title, markdown }` — it is never spliced
//! into a system prompt.
//!
//! Heavy deps (`reqwest`+rustls, the readability extractor + HTML→markdown
//! converter, the DNS resolver, tokio) live **only here**, behind the `web`
//! feature, so `agent-bridle-core` and a host's default build stay lean. The
//! crate compiles with `web` off (it then exposes nothing), so the workspace
//! builds under `--no-default-features`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "web")]
mod net_guard;
#[cfg(feature = "web")]
mod web_fetch;

#[cfg(feature = "web")]
pub use web_fetch::WebFetchTool;

// The net-screening predicates are pure and have no network or gate
// dependency; expose them so the host (and the CI presence/unit tests) can
// exercise the SSRF/allowlist logic directly.
#[cfg(feature = "web")]
pub use net_guard::{host_is_explicitly_allowlisted, ip_is_blocked, NetGuardError};
