//! The confined [`WebFetchTool`] — `web_fetch(url)` → structured markdown.

use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;

use agent_bridle_core::{Caveats, Scope, Tool, ToolContext, ToolError, ToolResult};
use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use url::Url;

use crate::net_guard::{screen_host, NetGuardError};

/// Maximum redirect hops followed before giving up. Each hop is independently
/// leash-screened (host allowlist + SSRF + IP pin).
const MAX_REDIRECTS: usize = 10;
/// Default cap on bytes read from a response body. Overridable per call via
/// `max_bytes`, but never above [`HARD_MAX_BYTES`].
const DEFAULT_MAX_BYTES: usize = 5 * 1024 * 1024;
/// Absolute ceiling on `max_bytes` regardless of the request.
const HARD_MAX_BYTES: usize = 25 * 1024 * 1024;

/// The tool's input schema, parsed once from the embedded `web_fetch.schema.json`
/// data file — the schema is *knowledge*, so it lives in plain-text data, not an
/// inline `json!` literal (three-Cs: knowledge in data, not logic). `include_str!`
/// binds it at compile time, so a malformed edit fails the build's tests, never a
/// live dispatch. The `max_bytes` ceiling is injected by [`Tool::schema`] from
/// [`HARD_MAX_BYTES`], keeping that bound's source of truth in Rust.
static WEB_SCHEMA: LazyLock<serde_json::Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("web_fetch.schema.json"))
        .expect("embedded web_fetch.schema.json must be valid JSON")
});
/// Per-request wall-clock timeout (bounds work; not a coordination primitive).
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// A web-fetch tool that retrieves a URL, follows redirects **under the leash**,
/// and returns the page's main content as markdown.
///
/// The `net` enforcement (DESIGN §7) runs before the first request and on every
/// redirect hop:
///
/// 1. the hop's host must satisfy the effective `net` caveat
///    ([`ToolContext::check_net`]);
/// 2. the host is resolved and its addresses are SSRF-screened — private /
///    loopback / link-local / unique-local addresses are rejected unless the
///    host is explicitly named in the `net` allowlist;
/// 3. the connection is **pinned** to a screened address (anti-rebinding);
/// 4. redirects are followed manually so each `Location` is re-screened, never
///    blindly trusted.
///
/// The returned body is **untrusted data**: `{ url, final_url, status, title,
/// markdown }`, never framed as instructions.
#[derive(Debug, Default, Clone, Copy)]
pub struct WebFetchTool;

impl WebFetchTool {
    /// Construct the tool.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Parsed, validated arguments for one fetch.
#[derive(Debug)]
struct FetchArgs {
    url: Url,
    max_bytes: usize,
}

impl FetchArgs {
    fn parse(args: &serde_json::Value) -> ToolResult<Self> {
        let raw = args
            .get("url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ToolError::denied("missing required string field `url`"))?;

        let url = Url::parse(raw)
            .map_err(|e| ToolError::denied(format!("`url` is not a valid URL: {e}")))?;

        // Only http(s) — the leash governs the `net` axis, not arbitrary URL
        // schemes (no file://, ftp://, gopher://, …, all of which are SSRF
        // vectors that bypass the host/IP screen entirely).
        match url.scheme() {
            "http" | "https" => {}
            other => {
                return Err(ToolError::denied(format!(
                    "unsupported URL scheme {other:?}: only http and https are allowed"
                )))
            }
        }

        let max_bytes = args
            .get("max_bytes")
            .and_then(serde_json::Value::as_u64)
            .map(|n| usize::try_from(n).unwrap_or(HARD_MAX_BYTES))
            .unwrap_or(DEFAULT_MAX_BYTES)
            .min(HARD_MAX_BYTES);

        Ok(Self { url, max_bytes })
    }
}

#[async_trait]
impl Tool for WebFetchTool {
    fn name(&self) -> &str {
        "web_fetch"
    }

    fn schema(&self) -> serde_json::Value {
        // Structure + descriptions live in the `web_fetch.schema.json` data file
        // (knowledge in data, not an inline literal); the `max_bytes` ceiling is
        // injected from the Rust-owned `HARD_MAX_BYTES` so the bound has one
        // source of truth.
        let mut schema = WEB_SCHEMA.clone();
        schema["properties"]["max_bytes"]["maximum"] =
            serde_json::Value::from(HARD_MAX_BYTES as u64);
        schema
    }

    /// `web_fetch` declares it needs **no** network authority by default — it
    /// runs under exactly the session grant. (The default `required()` is `top`;
    /// stating it here documents intent: confinement is the meet of grant and
    /// this ceiling.)
    fn required(&self) -> Caveats {
        Caveats::top()
    }

    async fn invoke(
        &self,
        args: serde_json::Value,
        cx: &ToolContext,
    ) -> ToolResult<serde_json::Value> {
        let parsed = FetchArgs::parse(&args)?;
        let original_url = parsed.url.clone();

        let resolver = build_resolver()?;
        let outcome = fetch_with_leashed_redirects(cx, &resolver, parsed).await?;

        // Extract the main content as markdown. Fetched bytes are DATA: we run
        // them through readability + HTML->markdown and return them in a
        // structured envelope, never as instructions.
        let (title, markdown) = extract_markdown(&outcome.body, outcome.final_url.as_str());

        Ok(serde_json::json!({
            "url": original_url.as_str(),
            "final_url": outcome.final_url.as_str(),
            "status": outcome.status,
            "title": title,
            "markdown": markdown,
        }))
    }
}

/// What a completed (leash-passing) fetch produced.
struct FetchOutcome {
    final_url: Url,
    status: u16,
    body: String,
}

/// Build a Tokio DNS resolver from the system config, falling back to a public
/// default if the system config cannot be read (e.g. minimal CI containers).
fn build_resolver() -> ToolResult<TokioAsyncResolver> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => Ok(r),
        Err(_) => Ok(TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        )),
    }
}

/// Resolve `host` to a set of IPs. A literal IP host is returned as-is (no DNS).
async fn resolve_host(resolver: &TokioAsyncResolver, host: &str) -> ToolResult<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    match resolver.lookup_ip(host).await {
        Ok(lookup) => Ok(lookup.iter().collect()),
        Err(e) => Err(ToolError::denied(format!(
            "could not resolve host {host:?}: {e}"
        ))),
    }
}

/// Fetch `start`, following redirects **manually** so the leash re-screens every
/// hop. Returns the final response body (capped at `max_bytes`).
async fn fetch_with_leashed_redirects(
    cx: &ToolContext,
    resolver: &TokioAsyncResolver,
    start: FetchArgs,
) -> ToolResult<FetchOutcome> {
    let max_bytes = start.max_bytes;
    let mut current = start.url;

    for _hop in 0..=MAX_REDIRECTS {
        let host = current
            .host_str()
            .ok_or_else(|| ToolError::denied("URL has no host"))?
            .to_string();
        let port = current
            .port_or_known_default()
            .ok_or_else(|| ToolError::denied("URL has no known port"))?;

        // (1) Host allowlist — default-deny, via the leash itself. This is the
        // ToolContext check; it consults the *effective* net caveat.
        cx.check_net(&host)?;

        // (2) Resolve + SSRF-screen against the same effective net scope. A
        // private/loopback IP is rejected unless the host is explicitly named.
        let resolved = resolve_host(resolver, &host).await?;
        let safe = screen_host(net_scope(cx), &host, &resolved).map_err(net_guard_to_tool)?;

        // (3) Pin the connection to a screened IP (anti-DNS-rebinding TOCTOU):
        // reqwest connects to exactly this address rather than re-resolving, so
        // a rebind between our check and the connect cannot redirect traffic.
        let pinned: Vec<SocketAddr> = safe.iter().map(|&ip| SocketAddr::new(ip, port)).collect();
        let client = build_pinned_client(&host, &pinned)?;

        // (4) Send with redirects DISABLED so we re-screen each Location.
        let resp = client
            .get(current.clone())
            .send()
            .await
            .map_err(|e| ToolError::denied(format!("request to {host:?} failed: {e}")))?;

        let status = resp.status();
        if status.is_redirection() {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    ToolError::denied(format!(
                        "{} redirect with no usable Location header",
                        status
                    ))
                })?;
            // Resolve the (possibly relative) Location against the current URL,
            // then loop — the next iteration re-runs steps (1)-(4) on the new
            // host. Never blindly follow.
            current = current.join(location).map_err(|e| {
                ToolError::denied(format!(
                    "redirect Location {location:?} is not a valid URL: {e}"
                ))
            })?;
            match current.scheme() {
                "http" | "https" => {}
                other => {
                    return Err(ToolError::denied(format!(
                        "redirect to unsupported scheme {other:?} denied"
                    )))
                }
            }
            continue;
        }

        // Terminal response: read the body (capped) and return.
        let final_url = resp.url().clone();
        let status_code = status.as_u16();
        let body = read_capped(resp, max_bytes).await?;
        return Ok(FetchOutcome {
            final_url,
            status: status_code,
            body,
        });
    }

    Err(ToolError::denied(format!(
        "too many redirects (>{MAX_REDIRECTS})"
    )))
}

/// Borrow the effective `net` scope out of the context.
fn net_scope(cx: &ToolContext) -> &Scope<String> {
    &cx.caveats().net
}

/// Map a [`NetGuardError`] to a leash denial (the agent-safe surface).
fn net_guard_to_tool(e: NetGuardError) -> ToolError {
    ToolError::denied(e.to_string())
}

/// Build a reqwest client pinned to `pinned` for `host`, with redirects off and
/// a request timeout. rustls (no openssl); we never auto-follow redirects.
fn build_pinned_client(host: &str, pinned: &[SocketAddr]) -> ToolResult<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        // Pin DNS for this host to the screened addresses (anti-rebinding).
        .resolve_to_addrs(host, pinned)
        // A modest UA so well-behaved servers respond; identifies the tool.
        .user_agent(concat!("agent-bridle-web/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| ToolError::denied(format!("could not build HTTP client: {e}")))
}

/// Read a response body to a UTF-8 string, capped at `max_bytes`.
///
/// Streams chunk-by-chunk with a hard byte budget rather than buffering the
/// whole body first: a hostile server that omits `Content-Length` cannot make
/// us allocate an unbounded body (a memory-DoS vector). The declared
/// `Content-Length`, when present, is an early-out so we never even start a body
/// that announces itself as too big.
async fn read_capped(mut resp: reqwest::Response, max_bytes: usize) -> ToolResult<String> {
    // Decline obviously-oversized bodies up front when the server declares one.
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(ToolError::denied(format!(
                "response body {len} bytes exceeds max_bytes {max_bytes}"
            )));
        }
    }

    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ToolError::denied(format!("reading response body failed: {e}")))?
    {
        let room = max_bytes.saturating_sub(buf.len());
        if chunk.len() > room {
            // Take what fits and stop — we never hold more than max_bytes.
            buf.extend_from_slice(&chunk[..room]);
            break;
        }
        buf.extend_from_slice(&chunk);
        if buf.len() >= max_bytes {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Run fetched HTML through the readability extractor, then convert the cleaned
/// main-article HTML to markdown. Returns `(title, markdown)`.
///
/// Best-effort: if readability cannot find a main article (e.g. a tiny test
/// page), we fall back to converting the whole document; if even that fails,
/// the markdown is the raw text. The caller always gets *some* data — the
/// security guarantees are upstream (the net leash), not in the extractor.
fn extract_markdown(html: &str, url: &str) -> (Option<String>, String) {
    use dom_smoothie::Readability;

    // Readability first: pull the main article + a clean title.
    if let Ok(mut readability) = Readability::new(html, Some(url), None) {
        if let Ok(article) = readability.parse() {
            let title = non_empty(article.title);
            let markdown = htmd::convert(&article.content)
                .unwrap_or_else(|_| article.text_content.to_string());
            if !markdown.trim().is_empty() {
                return (title, markdown);
            }
        }
    }

    // Fallback: convert the whole document.
    let markdown = htmd::convert(html).unwrap_or_else(|_| html.to_string());
    (None, markdown)
}

/// `Some(s)` unless `s` is empty/whitespace.
fn non_empty(s: String) -> Option<String> {
    if s.trim().is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridle_core::{CountBound, Gate};

    /// Mint a context for the web tool through the gate, the only legitimate
    /// way.
    fn authorize(granted: &Caveats) -> ToolResult<ToolContext> {
        Gate::new(0).authorize(&WebFetchTool::new(), granted)
    }

    fn loopback_grant() -> Caveats {
        // 127.0.0.1 explicitly allowlisted -> opted into loopback space.
        Caveats {
            net: Scope::only(["127.0.0.1".to_string()]),
            max_calls: CountBound::AtMost(5),
            ..Caveats::top()
        }
    }

    #[test]
    fn schema_requires_url_and_forbids_extras() {
        let s = WebFetchTool::new().schema();
        assert_eq!(s["properties"]["url"]["type"], "string");
        assert_eq!(s["required"][0], "url");
        assert_eq!(s["additionalProperties"], false);
        // The `max_bytes` ceiling is injected from HARD_MAX_BYTES over the
        // data-file base (the file itself carries no `maximum`).
        assert_eq!(
            s["properties"]["max_bytes"]["maximum"],
            HARD_MAX_BYTES as u64
        );
        assert!(WEB_SCHEMA["properties"]["max_bytes"]
            .get("maximum")
            .is_none());
    }

    #[test]
    fn parse_rejects_non_http_schemes() {
        // file:// and friends are SSRF vectors that bypass the host/IP screen.
        for bad in ["file:///etc/passwd", "ftp://x/y", "gopher://h/0"] {
            let err = FetchArgs::parse(&serde_json::json!({ "url": bad })).unwrap_err();
            assert!(matches!(err, ToolError::Denied { .. }), "{bad}: {err:?}");
        }
    }

    #[test]
    fn parse_caps_max_bytes_at_hard_ceiling() {
        let p = FetchArgs::parse(&serde_json::json!({
            "url": "http://example.com",
            "max_bytes": (HARD_MAX_BYTES as u64) * 4
        }))
        .unwrap();
        assert_eq!(p.max_bytes, HARD_MAX_BYTES);
    }

    #[tokio::test]
    async fn host_not_in_scope_is_denied_before_any_request() {
        // net = Only{example.com}; a fetch to 127.0.0.1 must be denied by the
        // host allowlist (and never reach the network).
        let granted = Caveats {
            net: Scope::only(["example.com".to_string()]),
            ..Caveats::top()
        };
        let cx = authorize(&granted).unwrap();
        let err = WebFetchTool::new()
            .invoke(serde_json::json!({ "url": "http://127.0.0.1:1/" }), &cx)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn private_ip_denied_when_host_permitted_but_not_optedin() {
        // net = All permits the host string, but does not opt it into private
        // space, so a literal private IP host is SSRF-blocked. (No DNS, no
        // network — the literal IP is screened directly.)
        let granted = Caveats {
            net: Scope::All,
            ..Caveats::top()
        };
        let cx = authorize(&granted).unwrap();
        let err = WebFetchTool::new()
            .invoke(serde_json::json!({ "url": "http://10.0.0.1/" }), &cx)
            .await
            .unwrap_err();
        match err {
            ToolError::Denied { reason } => {
                assert!(
                    reason.contains("SSRF"),
                    "expected SSRF denial, got {reason:?}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn extract_markdown_converts_simple_html() {
        let html = "<html><head><title>Hi</title></head><body><h1>Heading</h1>\
            <p>Hello <b>world</b>.</p></body></html>";
        let (_title, md) = extract_markdown(html, "http://example.com/");
        assert!(md.contains("Heading"), "markdown was {md:?}");
        assert!(md.contains("world"), "markdown was {md:?}");
    }

    #[test]
    fn loopback_grant_opts_in_127() {
        // Sanity: the grant we use in integration tests really does opt 127 in.
        let g = loopback_grant();
        assert!(crate::net_guard::host_is_explicitly_allowlisted(
            &g.net,
            "127.0.0.1"
        ));
    }
}
