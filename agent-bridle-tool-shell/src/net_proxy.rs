//! Loopback egress proxy for the macOS `net` host allow-list (#124, ADR 0016).
//!
//! SBPL cannot name a remote host (ADR 0015), so a general `net: Only([host, …])`
//! grant cannot be kernel-confined by hostname. The honest mechanism: kernel-fence
//! a spawned child's egress to the **loopback interface** (the ADR 0015 rule, via
//! [`agent_bridle_core::loopback_fenced_caveats`]), then run **this** loopback
//! forward proxy — which the child is pointed at through `*_PROXY` env — to enforce
//! the hostname allow-list. The child can reach *nothing* off-box except through
//! the proxy, and the proxy admits only allow-listed hosts.
//!
//! **Grade (honesty):** the loopback fence is kernel-grade and unbypassable; the
//! hostname match is **userspace** (this parent-side process). So the `net` axis
//! stays reported `Advisory` — the proxy *over-delivers* above that floor (the
//! `report.rs` doctrine), it does not raise the honest kernel claim.
//!
//! **Scope:** HTTP `CONNECT` (HTTPS tunnelling — the proxy never terminates TLS)
//! and `http://` absolute-form forwarding. Non-proxy-aware traffic (raw sockets,
//! tools ignoring `*_PROXY`) is kernel-fenced to loopback and therefore blocked
//! off-box — fail-closed, the safe direction.
//!
//! Std-only (`std::net` + `std::thread`); no async runtime, no new dependency —
//! so [`ProxyHandle`] is a plain RAII value whose `Drop` tears the listener down.

use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Longest request line / header block the proxy will buffer before giving up
/// (a request line is short; this only bounds a hostile client). 8 KiB.
const MAX_HEAD: usize = 8 * 1024;
/// Per-connection socket timeout, so a stuck peer cannot pin a proxy thread.
const CONN_TIMEOUT: Duration = Duration::from_secs(30);

// ── Audit (#124, ADR 0016): the proxy is the child's sole egress chokepoint, so
// every proxy-visible connection is recorded through an operator-supplied sink.
// This is observability only — it never changes an enforcement decision. ────────

/// The kind of egress a child requested through the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetKind {
    /// `CONNECT host:port` — an opaque (HTTPS) tunnel.
    Connect,
    /// `http://…` plaintext forward.
    Http,
}

/// The proxy's allow-list decision for one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetDecision {
    /// Host on the allow-list — connection made.
    Allowed,
    /// Host **not** on the allow-list — refused with 403 (the exfil-attempt signal).
    Denied,
    /// Allow-listed but the origin could not be reached (DNS/connect failure).
    Error,
}

/// One audited egress connection through the proxy — a complete record of the
/// child's proxy-visible network activity (#124, ADR 0016). Serialised as one
/// JSON line by [`JsonlSink`]; the `bridle-netmon` binary renders a live view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetAuditEvent {
    /// Unix-epoch milliseconds when the connection was decided.
    pub ts_ms: u64,
    /// The requested host (CONNECT authority or `http://` URI host).
    pub host: String,
    /// The requested port.
    pub port: u16,
    /// Tunnel (`connect`) or plaintext forward (`http`).
    pub kind: NetKind,
    /// Allow-list outcome.
    pub decision: NetDecision,
    /// Bytes the child sent (client → origin); `0` for a denied/errored conn.
    pub bytes_up: u64,
    /// Bytes the origin returned (origin → child).
    pub bytes_down: u64,
    /// Connection lifetime in milliseconds.
    pub dur_ms: u64,
}

/// A destination for [`NetAuditEvent`]s — the operator's audit trail. `record` is
/// called from a per-connection thread, so implementations must be thread-safe
/// and must never block the connection for long.
pub trait AuditSink: Send + Sync {
    /// Record one completed connection.
    fn record(&self, event: &NetAuditEvent);
}

/// The default sink — discard everything (audit off, zero overhead).
pub struct NullSink;

impl AuditSink for NullSink {
    fn record(&self, _event: &NetAuditEvent) {}
}

/// Append each event as one JSON line to a `Write` (a file, stderr, a pipe).
pub struct JsonlSink<W: Write + Send>(Mutex<W>);

impl<W: Write + Send> JsonlSink<W> {
    /// Wrap a writer as a JSON-lines audit sink.
    pub fn new(w: W) -> Self {
        Self(Mutex::new(w))
    }
}

impl<W: Write + Send> AuditSink for JsonlSink<W> {
    fn record(&self, event: &NetAuditEvent) {
        if let (Ok(mut w), Ok(mut line)) = (self.0.lock(), serde_json::to_string(event)) {
            line.push('\n');
            let _ = w.write_all(line.as_bytes());
            let _ = w.flush();
        }
    }
}

/// Unix-epoch milliseconds now (saturating to 0 before the epoch — never panics).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Resolves a proxied hostname to the address the proxy dials. A seam so a test
/// can map an allow-listed name to a loopback origin (hermetic, no real DNS).
pub trait Resolver: Send + Sync {
    /// Resolve `host:port` to a single dial target, or an error if it cannot.
    fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr>;
}

/// The production resolver — the platform's own `getaddrinfo`, run in the parent
/// (never the fenced child), taking the first address.
pub struct StdResolver;

impl Resolver for StdResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for host"))
    }
}

/// What a client's first request line asked for.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// `CONNECT host:port HTTP/x` — a TLS tunnel to open.
    Connect { host: String, port: u16 },
    /// `METHOD http://host[:port]/path HTTP/x` — a plaintext request to forward;
    /// `origin_line` is the same line rewritten to origin-form (`METHOD /path …`).
    Http {
        host: String,
        port: u16,
        origin_line: String,
    },
}

/// Parse a proxy request line. Returns `None` on anything malformed or a scheme
/// the proxy does not speak (only `CONNECT` and `http://` absolute-form).
fn parse_request_line(line: &str) -> Option<Target> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let uri = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return None;
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(uri, 443)?;
        return Some(Target::Connect { host, port });
    }
    // Absolute-form: METHOD http://host[:port]/path HTTP/x  (proxy requests only).
    let rest = uri.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_host_port(authority, 80)?;
    Some(Target::Http {
        host,
        port,
        origin_line: format!("{method} {path} {version}\r\n"),
    })
}

/// Split `host:port` (or a bare host, or a bracketed IPv6 literal) into
/// `(host, port)`, defaulting the port. Returns `None` on an unparsable port.
fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    // Bracketed IPv6 literal: [::1] or [::1]:8080
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        // Host part still holds a ':' → an unbracketed IPv6 literal ("::1"); take
        // the whole authority as the host at the default port (fail-safe: a weird
        // string just misses the exact-name allow-list).
        Some((h, _)) if h.contains(':') => Some((authority.to_string(), default_port)),
        // ":443" — no host.
        Some(("", _)) => None,
        // A single ':' → host:port; a non-numeric port is malformed (reject).
        Some((h, p)) => Some((h.to_string(), p.parse::<u16>().ok()?)),
        // No ':' → a bare host at the default port.
        None => Some((authority.to_string(), default_port)),
    }
}

/// The exact-hostname allow-list, mirroring `ToolContext::check_net`'s membership.
#[derive(Clone)]
struct HostPolicy(Arc<HashSet<String>>);

impl HostPolicy {
    fn new(hosts: impl IntoIterator<Item = String>) -> Self {
        Self(Arc::new(hosts.into_iter().collect()))
    }
    fn allows(&self, host: &str) -> bool {
        self.0.contains(host)
    }
}

/// A running loopback egress proxy. Dropping the handle shuts it down.
pub struct ProxyHandle {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl ProxyHandle {
    /// The loopback address the fenced child is pointed at. Only tests read it
    /// directly; production wires the child via [`Self::proxy_env`].
    #[cfg(test)]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The `*_PROXY` environment the child needs to route through this proxy.
    /// Both cases are set: curl honours lowercase `http_proxy` (it ignores the
    /// uppercase form for CGI-safety) but uppercase `HTTPS_PROXY`/`ALL_PROXY`;
    /// other tools (wget, requests, node) read the rest.
    #[must_use]
    pub fn proxy_env(&self) -> Vec<(String, String)> {
        let url = format!("http://{}", self.addr);
        [
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
        ]
        .iter()
        .map(|k| ((*k).to_string(), url.clone()))
        .collect()
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Wake the blocking `accept()` so the loop observes the flag and exits.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
    }
}

/// Start a loopback forward proxy that admits only `allow_hosts`, resolving via
/// `resolver` and auditing every connection through `sink` ([`NullSink`] for no
/// audit). Binds `127.0.0.1:0` (an ephemeral port — concurrent runs never
/// collide) and serves until the returned [`ProxyHandle`] is dropped.
///
/// Fail-closed: an error binding the listener is returned so the caller refuses
/// the run rather than spawning an unfenced child.
pub fn start(
    allow_hosts: impl IntoIterator<Item = String>,
    resolver: Arc<dyn Resolver>,
    sink: Arc<dyn AuditSink>,
) -> io::Result<ProxyHandle> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let addr = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let policy = HostPolicy::new(allow_hosts);

    let accept = {
        let shutdown = Arc::clone(&shutdown);
        thread::Builder::new()
            .name("agent-bridle-egress-proxy".to_string())
            .spawn(move || {
                for stream in listener.incoming() {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(client) = stream else { continue };
                    let policy = policy.clone();
                    let resolver = Arc::clone(&resolver);
                    let sink = Arc::clone(&sink);
                    // One detached thread per connection; it ends at EOF.
                    let _ = thread::Builder::new()
                        .name("agent-bridle-egress-conn".to_string())
                        .spawn(move || {
                            let _ = handle_conn(client, &policy, resolver.as_ref(), sink.as_ref());
                        });
                }
            })?
    };

    Ok(ProxyHandle {
        addr,
        shutdown,
        accept: Some(accept),
    })
}

/// Serve one client connection: parse its request line, enforce the allow-list,
/// and either tunnel (`CONNECT`) or forward (`http://`) to the resolved origin.
/// Every connection with a parsed host is recorded through `sink`.
fn handle_conn(
    client: TcpStream,
    policy: &HostPolicy,
    resolver: &dyn Resolver,
    sink: &dyn AuditSink,
) -> io::Result<()> {
    client.set_read_timeout(Some(CONN_TIMEOUT))?;
    client.set_write_timeout(Some(CONN_TIMEOUT))?;
    let mut reader = BufReader::new(client.try_clone()?);
    let t0 = Instant::now();

    let line = read_line_bounded(&mut reader)?;
    let Some(target) = parse_request_line(&line) else {
        // No host to attribute — a malformed request is not an egress event.
        return respond(&client, 400, "Bad Request");
    };

    let (host, port, kind) = match &target {
        Target::Connect { host, port } => (host.clone(), *port, NetKind::Connect),
        Target::Http { host, port, .. } => (host.clone(), *port, NetKind::Http),
    };
    // Emit the audit record once, whatever the outcome.
    let audit = |decision: NetDecision, up: u64, down: u64| {
        sink.record(&NetAuditEvent {
            ts_ms: now_ms(),
            host: host.clone(),
            port,
            kind,
            decision,
            bytes_up: up,
            bytes_down: down,
            dur_ms: t0.elapsed().as_millis() as u64,
        });
    };

    if !policy.allows(&host) {
        audit(NetDecision::Denied, 0, 0); // the exfil-attempt signal
        return respond(&client, 403, "Forbidden");
    }

    match target {
        Target::Connect { host, port } => {
            // CONNECT: drain the remaining request headers (up to the blank line)
            // before the tunnel begins — the client waits for our 200 first.
            drain_headers(&mut reader)?;
            let origin = match resolver.resolve(&host, port).and_then(dial) {
                Ok(o) => o,
                Err(_) => {
                    audit(NetDecision::Error, 0, 0);
                    return respond(&client, 502, "Bad Gateway");
                }
            };
            // A CONNECT success is a *bare* status line — no body, no
            // `Content-Length` — after which the socket is an opaque tunnel. (Do
            // NOT use `respond`, which appends a body that would corrupt it.)
            (&client).write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
            let (up, down) = tunnel(client, origin)?;
            audit(NetDecision::Allowed, up, down);
            Ok(())
        }
        Target::Http {
            host,
            port,
            origin_line,
        } => {
            // Read the client's request headers and **drop any client-supplied
            // Host** — an attacker could send `Host: disallowed.com` to domain-front
            // off a shared/CDN origin at the allow-listed IP. Substitute the proxy's
            // own Host, derived from the *validated* authority, so the origin only
            // ever sees the host the allow-list approved.
            let headers = read_headers(&mut reader)?;
            let mut origin = match resolver.resolve(&host, port).and_then(dial) {
                Ok(o) => o,
                Err(_) => {
                    audit(NetDecision::Error, 0, 0);
                    return respond(&client, 502, "Bad Gateway");
                }
            };
            let host_hdr = if port == 80 {
                format!("Host: {host}\r\n")
            } else {
                format!("Host: {host}:{port}\r\n")
            };
            origin.write_all(origin_line.as_bytes())?;
            origin.write_all(host_hdr.as_bytes())?;
            for h in &headers {
                if !h.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("host:")) {
                    origin.write_all(h.as_bytes())?;
                }
            }
            origin.write_all(b"\r\n")?; // end of the (rewritten) header block
            let (up, down) = splice_buffered(reader, client, origin)?; // forward the body
            audit(NetDecision::Allowed, up, down);
            Ok(())
        }
    }
}

/// Dial a resolved origin with a bounded connect timeout.
fn dial(addr: SocketAddr) -> io::Result<TcpStream> {
    let s = TcpStream::connect_timeout(&addr, CONN_TIMEOUT)?;
    s.set_read_timeout(Some(CONN_TIMEOUT))?;
    s.set_write_timeout(Some(CONN_TIMEOUT))?;
    Ok(s)
}

/// Read one CRLF-terminated line, bounded to [`MAX_HEAD`].
fn read_line_bounded(reader: &mut BufReader<TcpStream>) -> io::Result<String> {
    let mut buf = Vec::new();
    reader.take(MAX_HEAD as u64).read_until(b'\n', &mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Read request header lines up to (not including) the terminating blank line,
/// bounded by [`MAX_HEAD`]. Each returned line keeps its trailing CRLF.
fn read_headers(reader: &mut BufReader<TcpStream>) -> io::Result<Vec<String>> {
    let mut lines = Vec::new();
    let mut total = 0usize;
    loop {
        let line = read_line_bounded(reader)?;
        total += line.len();
        if line == "\r\n" || line == "\n" || line.is_empty() || total > MAX_HEAD {
            return Ok(lines);
        }
        lines.push(line);
    }
}

/// Consume request headers up to and including the terminating blank line.
fn drain_headers(reader: &mut BufReader<TcpStream>) -> io::Result<()> {
    let mut total = 0usize;
    loop {
        let line = read_line_bounded(reader)?;
        total += line.len();
        if line == "\r\n" || line == "\n" || line.is_empty() || total > MAX_HEAD {
            return Ok(());
        }
    }
}

/// Write a minimal HTTP/1.1 status response and close.
fn respond(client: &TcpStream, code: u16, reason: &str) -> io::Result<()> {
    let mut c = client.try_clone()?;
    let body = format!("{code} {reason}\n");
    write!(
        c,
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let _ = c.flush();
    let _ = client.shutdown(Shutdown::Both);
    Ok(())
}

/// Copy `from` → `to`, returning the bytes **forwarded** — preserved even if a
/// stream errors mid-copy (a reset after data still counts what flowed), so the
/// audit totals are not silently zeroed by an abrupt close (`std::io::copy`
/// discards its count on error). Stops at EOF, a write failure, or a read error.
fn copy_counted(from: &mut impl Read, to: &mut impl Write) -> u64 {
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
                total += n as u64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    total
}

/// Bidirectional raw byte tunnel between `client` and `origin` (the `CONNECT`
/// case): two copy threads, each shutting its write half at EOF. Returns
/// `(bytes_up, bytes_down)` — child→origin and origin→child — for the audit.
fn tunnel(client: TcpStream, origin: TcpStream) -> io::Result<(u64, u64)> {
    let mut c_read = client.try_clone()?;
    let mut o_write = origin.try_clone()?;
    let up = thread::spawn(move || {
        let n = copy_counted(&mut c_read, &mut o_write);
        let _ = o_write.shutdown(Shutdown::Write);
        n
    });
    let mut o_read = origin;
    let mut c_write = client;
    let down = copy_counted(&mut o_read, &mut c_write);
    let _ = c_write.shutdown(Shutdown::Write);
    let up = up.join().unwrap_or(0);
    Ok((up, down))
}

/// Like [`tunnel`] but the client side is a `BufReader` that may already hold
/// buffered bytes (the `http://` forward case, after the request line was read).
/// Returns `(bytes_up, bytes_down)` for the audit.
fn splice_buffered(
    mut client_reader: BufReader<TcpStream>,
    client: TcpStream,
    origin: TcpStream,
) -> io::Result<(u64, u64)> {
    let mut o_write = origin.try_clone()?;
    let up = thread::spawn(move || {
        let n = copy_counted(&mut client_reader, &mut o_write);
        let _ = o_write.shutdown(Shutdown::Write);
        n
    });
    let mut o_read = origin;
    let mut c_write = client;
    let down = copy_counted(&mut o_read, &mut c_write);
    let _ = c_write.shutdown(Shutdown::Write);
    let up = up.join().unwrap_or(0);
    Ok((up, down))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect() {
        assert_eq!(
            parse_request_line("CONNECT example.com:443 HTTP/1.1\r\n"),
            Some(Target::Connect {
                host: "example.com".to_string(),
                port: 443
            })
        );
        // Default port when omitted.
        assert_eq!(
            parse_request_line("CONNECT example.com HTTP/1.1"),
            Some(Target::Connect {
                host: "example.com".to_string(),
                port: 443
            })
        );
    }

    #[test]
    fn parses_http_absolute_form_and_rewrites_to_origin_form() {
        let t = parse_request_line("GET http://example.com/a/b?q=1 HTTP/1.1\r\n").unwrap();
        assert_eq!(
            t,
            Target::Http {
                host: "example.com".to_string(),
                port: 80,
                origin_line: "GET /a/b?q=1 HTTP/1.1\r\n".to_string(),
            }
        );
        // No path → "/". Explicit port honoured.
        let t = parse_request_line("HEAD http://h:8080 HTTP/1.0").unwrap();
        assert_eq!(
            t,
            Target::Http {
                host: "h".to_string(),
                port: 8080,
                origin_line: "HEAD / HTTP/1.0\r\n".to_string(),
            }
        );
    }

    #[test]
    fn parses_ipv6_authority() {
        assert_eq!(
            parse_request_line("CONNECT [::1]:8443 HTTP/1.1"),
            Some(Target::Connect {
                host: "::1".to_string(),
                port: 8443
            })
        );
    }

    #[test]
    fn rejects_malformed_and_unspoken_schemes() {
        assert!(parse_request_line("GET / HTTP/1.1").is_none()); // origin-form, not a proxy req
        assert!(parse_request_line("GET https://x/ HTTP/1.1").is_none()); // https absolute-form
        assert!(parse_request_line("GET ftp://x/ HTTP/1.1").is_none());
        assert!(parse_request_line("garbage").is_none());
        assert!(parse_request_line("CONNECT x:notaport HTTP/1.1").is_none());
    }

    /// A resolver that maps every name to a fixed loopback origin — hermetic.
    struct FixedResolver(SocketAddr);
    impl Resolver for FixedResolver {
        fn resolve(&self, _host: &str, _port: u16) -> io::Result<SocketAddr> {
            Ok(self.0)
        }
    }

    /// Start the proxy with no audit sink (most tests don't inspect the audit).
    fn start_null(
        hosts: impl IntoIterator<Item = String>,
        resolver: Arc<dyn Resolver>,
    ) -> io::Result<ProxyHandle> {
        start(hosts, resolver, Arc::new(NullSink))
    }

    /// An audit sink that collects every event into a shared vec, for assertions.
    #[derive(Clone, Default)]
    struct CapturingSink(Arc<Mutex<Vec<NetAuditEvent>>>);
    impl AuditSink for CapturingSink {
        fn record(&self, event: &NetAuditEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }
    impl CapturingSink {
        fn events(&self) -> Vec<NetAuditEvent> {
            self.0.lock().unwrap().clone()
        }
    }

    /// Serialize the networky proxy tests. Each spins up its own origin + proxy
    /// accept-loops; running them concurrently under the full-suite `just check`
    /// contends enough that one connection's **close-time** audit can be starved
    /// (flaky in the pre-push hook, though each passes instantly in isolation —
    /// loadavg stays low, so it is interleaving, not CPU). A single shared lock
    /// runs them one-at-a-time. Poison is ignored so a panicking test does not
    /// cascade-fail the rest. (The underlying audit-under-contention robustness is
    /// tracked separately in #138.)
    fn net_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A one-shot HTTP origin on loopback that replies 200 with a marker body.
    fn spawn_origin() -> SocketAddr {
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut s = s;
                let mut b = [0u8; 512];
                let _ = s.read(&mut b);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin",
                );
            }
        });
        addr
    }

    fn http_get_via_proxy(proxy: SocketAddr, url: &str) -> (String, Vec<u8>) {
        let mut c = TcpStream::connect(proxy).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        write!(
            c,
            "GET {url} HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut resp = Vec::new();
        let _ = c.read_to_end(&mut resp);
        let status = String::from_utf8_lossy(&resp)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string();
        (status, resp)
    }

    #[test]
    fn allowed_http_host_is_forwarded_to_origin() {
        let _serial = net_test_lock();
        let origin = spawn_origin();
        let proxy = start_null(
            ["allowed.test".to_string()],
            Arc::new(FixedResolver(origin)),
        )
        .unwrap();
        let (status, body) = http_get_via_proxy(proxy.addr(), "http://allowed.test/x");
        assert!(status.contains("200"), "status={status}");
        assert!(
            String::from_utf8_lossy(&body).contains("origin"),
            "the origin's body must reach the client: {status}"
        );
    }

    #[test]
    fn disallowed_http_host_is_refused_403_without_reaching_origin() {
        let _serial = net_test_lock();
        // No origin needed — a denied host must never be dialled.
        let proxy = start_null(
            ["allowed.test".to_string()],
            Arc::new(FixedResolver("127.0.0.1:1".parse().unwrap())),
        )
        .unwrap();
        let (status, _) = http_get_via_proxy(proxy.addr(), "http://evil.test/x");
        assert!(status.contains("403"), "denied host must get 403: {status}");
    }

    #[test]
    fn audit_records_allowed_with_bytes_and_denied_attempts() {
        let _serial = net_test_lock();
        let origin = spawn_origin();
        let sink = CapturingSink::default();
        let proxy = start(
            ["allowed.test".to_string()],
            Arc::new(FixedResolver(origin)),
            Arc::new(sink.clone()),
        )
        .unwrap();
        let _ = http_get_via_proxy(proxy.addr(), "http://allowed.test/x");
        let _ = http_get_via_proxy(proxy.addr(), "http://evil.test/y"); // denied

        // The connection threads are detached, so poll (not a fixed sleep) until
        // both records land — robust under parallel-test load.
        // Generous headroom: under the pre-push hook's parallel full-suite load the
        // proxy→origin round-trip + detached audit thread can exceed a tight bound;
        // match the production CONN_TIMEOUT so a busy host never spuriously fails.
        let deadline = Instant::now() + Duration::from_secs(30);
        let events = loop {
            let ev = sink.events();
            let have = |h: &str| ev.iter().any(|e| e.host == h);
            if (have("allowed.test") && have("evil.test")) || Instant::now() >= deadline {
                break ev;
            }
            thread::sleep(Duration::from_millis(20));
        };
        let allowed = events
            .iter()
            .find(|e| e.host == "allowed.test")
            .expect("an allowed event");
        assert_eq!(allowed.decision, NetDecision::Allowed);
        assert_eq!(allowed.kind, NetKind::Http);
        assert_eq!(allowed.port, 80);
        assert!(
            allowed.bytes_down > 0,
            "an allowed connection records response bytes: {allowed:?}"
        );

        let denied = events
            .iter()
            .find(|e| e.host == "evil.test")
            .expect("a denied event (the exfil-attempt signal)");
        assert_eq!(denied.decision, NetDecision::Denied);
        assert_eq!(denied.bytes_up, 0);
        assert_eq!(denied.bytes_down, 0);
    }

    #[test]
    fn jsonl_sink_appends_one_newline_terminated_json_line_per_event() {
        #[derive(Clone, Default)]
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedBuf {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let buf = SharedBuf::default();
        let sink = JsonlSink::new(buf.clone());
        let mk = |host: &str| NetAuditEvent {
            ts_ms: 1,
            host: host.into(),
            port: 80,
            kind: NetKind::Http,
            decision: NetDecision::Allowed,
            bytes_up: 1,
            bytes_down: 2,
            dur_ms: 3,
        };
        sink.record(&mk("a"));
        sink.record(&mk("b"));
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one JSON line per event: {text:?}");
        assert_eq!(
            serde_json::from_str::<NetAuditEvent>(lines[0])
                .unwrap()
                .host,
            "a"
        );
        assert_eq!(
            serde_json::from_str::<NetAuditEvent>(lines[1])
                .unwrap()
                .host,
            "b"
        );
    }

    #[test]
    fn audit_event_json_round_trips() {
        let e = NetAuditEvent {
            ts_ms: 1,
            host: "h".into(),
            port: 443,
            kind: NetKind::Connect,
            decision: NetDecision::Allowed,
            bytes_up: 10,
            bytes_down: 20,
            dur_ms: 5,
        };
        let line = serde_json::to_string(&e).unwrap();
        assert!(line.contains("\"decision\":\"allowed\"") && line.contains("\"kind\":\"connect\""));
        assert_eq!(serde_json::from_str::<NetAuditEvent>(&line).unwrap(), e);
    }

    /// A one-shot raw-TCP echo origin (no HTTP), to prove the `CONNECT` tunnel
    /// forwards opaque bytes in both directions (as it would TLS records).
    fn spawn_echo() -> SocketAddr {
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut s = s;
                let mut b = [0u8; 64];
                if let Ok(n) = s.read(&mut b) {
                    let _ = s.write_all(&b[..n]);
                }
            }
        });
        addr
    }

    #[test]
    fn connect_allowed_host_tunnels_opaque_bytes() {
        let _serial = net_test_lock();
        let echo = spawn_echo();
        let proxy =
            start_null(["allowed.test".to_string()], Arc::new(FixedResolver(echo))).unwrap();
        let mut c = TcpStream::connect(proxy.addr()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        write!(
            c,
            "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n"
        )
        .unwrap();
        // The proxy answers a bare 200 status line (ending in the blank line),
        // then the raw stream is an end-to-end tunnel. Read the header block.
        let mut status = BufReader::new(c.try_clone().unwrap());
        let mut head = String::new();
        loop {
            let mut l = String::new();
            status.read_line(&mut l).unwrap();
            if l == "\r\n" || l.is_empty() {
                break;
            }
            head.push_str(&l);
        }
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "CONNECT must be accepted with a bare 200: {head:?}"
        );
        // Opaque bytes tunnel through to the echo origin and back.
        c.write_all(b"PING").unwrap();
        let mut back = [0u8; 4];
        status.read_exact(&mut back).unwrap();
        assert_eq!(
            &back, b"PING",
            "the tunnel must forward raw bytes both ways"
        );
    }

    #[test]
    fn connect_disallowed_host_is_refused_403() {
        let _serial = net_test_lock();
        let proxy = start_null(
            ["allowed.test".to_string()],
            Arc::new(FixedResolver("127.0.0.1:1".parse().unwrap())),
        )
        .unwrap();
        let mut c = TcpStream::connect(proxy.addr()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        write!(c, "CONNECT evil.test:443 HTTP/1.1\r\n\r\n").unwrap();
        let mut resp = Vec::new();
        let _ = c.read_to_end(&mut resp);
        assert!(
            String::from_utf8_lossy(&resp).contains("403"),
            "a denied CONNECT must get 403, not a tunnel: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// A one-shot origin that echoes back the `Host` header it received.
    fn spawn_host_echo() -> SocketAddr {
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut s = s;
                let mut reader = BufReader::new(s.try_clone().unwrap());
                let mut host = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.get(..5).filter(|p| p.eq_ignore_ascii_case("host:")) {
                        let _ = v;
                        host = line[5..].trim().to_string();
                    }
                }
                let body = format!("host={host}");
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        addr
    }

    #[test]
    fn http_host_header_is_normalized_to_the_validated_authority() {
        let _serial = net_test_lock();
        let origin = spawn_host_echo();
        let proxy = start_null(
            ["allowed.test".to_string()],
            Arc::new(FixedResolver(origin)),
        )
        .unwrap();
        // The authority (allowed.test) is validated, but the client LIES with a
        // spoofed `Host: evil.test` to domain-front. The origin must see the
        // validated authority, never the spoof.
        let mut c = TcpStream::connect(proxy.addr()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        write!(
            c,
            "GET http://allowed.test/ HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut resp = Vec::new();
        let _ = c.read_to_end(&mut resp);
        let resp = String::from_utf8_lossy(&resp);
        assert!(
            resp.contains("host=allowed.test"),
            "origin must receive the validated Host: {resp}"
        );
        assert!(
            !resp.contains("evil.test"),
            "the spoofed Host must not reach the origin: {resp}"
        );
    }

    #[test]
    fn proxy_env_points_at_the_bound_loopback_addr() {
        let _serial = net_test_lock();
        let proxy = start_null(["x".to_string()], Arc::new(StdResolver)).unwrap();
        let env = proxy.proxy_env();
        let url = format!("http://127.0.0.1:{}", proxy.addr().port());
        assert!(env.iter().any(|(k, v)| k == "https_proxy" && *v == url));
        assert!(env.iter().any(|(k, v)| k == "HTTPS_PROXY" && *v == url));
        assert!(env.iter().all(|(_, v)| v.starts_with("http://127.0.0.1:")));
    }

    /// End-to-end kernel proof (#124, ADR 0016): a real `curl` child, confined by
    /// the ADR 0015 loopback fence, reaches an ALLOWED host only through the proxy
    /// (200), is refused a DENIED host by the proxy (403), and — crucially —
    /// **cannot bypass** the proxy: a direct off-box connect is kernel-denied. All
    /// hermetic — the resolver maps the allow-listed name to a loopback origin, so
    /// no real network is touched. macOS + `macos-seatbelt` only; self-skips if
    /// `sandbox-exec`/`curl` are unavailable.
    #[cfg(all(target_os = "macos", feature = "macos-seatbelt"))]
    #[test]
    fn fenced_child_reaches_allowed_via_proxy_denied_refused_direct_kernel_blocked() {
        use agent_bridle_core::{
            best_available_sandbox, loopback_fenced_caveats, seatbelt_is_supported, Caveats, Scope,
        };
        if !seatbelt_is_supported() {
            eprintln!("skipping: /usr/bin/sandbox-exec unavailable");
            return;
        }
        let curl = "/usr/bin/curl";
        if !std::path::Path::new(curl).exists() {
            eprintln!("skipping: no curl(1)");
            return;
        }

        let origin = spawn_origin();
        let proxy = start_null(
            ["allowed.test".to_string()],
            Arc::new(FixedResolver(origin)),
        )
        .unwrap();

        // The grant is a general remote-host allow-list; its loopback-fenced form
        // is what actually confines the child (the ADR 0016 mechanism).
        let granted = Caveats {
            net: Scope::only(["allowed.test".to_string()]),
            ..Caveats::top()
        };
        let prefix = best_available_sandbox()
            .command_prefix(&loopback_fenced_caveats(&granted))
            .expect("seatbelt wrapper");

        // Run `curl` wrapped by the fence, with the given env. `-v` surfaces the
        // connect-time error on stderr so the FENCE leg can assert a *permission*
        // denial (not a mere routing failure).
        let run = |proxy_env: bool, url: &str| -> std::process::Output {
            let mut cmd = std::process::Command::new(&prefix[0]);
            cmd.args(&prefix[1..])
                .arg(curl)
                .args(["-sv", "--max-time", "5", url])
                .env_clear();
            if proxy_env {
                cmd.envs(proxy.proxy_env());
            }
            cmd.output().expect("spawn sandbox-exec")
        };

        // ALLOW: via the proxy, the allow-listed host reaches the loopback origin.
        let allow = run(true, "http://allowed.test/");
        assert!(
            String::from_utf8_lossy(&allow.stdout).contains("origin"),
            "allow-listed host must reach the origin through the proxy: {allow:?}"
        );
        // DENY: via the proxy, a non-allow-listed host gets the proxy's 403 — and
        // never reaches any origin.
        let deny = run(true, "http://denied.test/");
        assert!(
            String::from_utf8_lossy(&deny.stdout).contains("403"),
            "denied host must get the proxy's 403: {deny:?}"
        );
        // FENCE: WITHOUT the proxy env the child tries to egress directly; a literal
        // off-box IP is kernel-denied at the socket. Assert curl exit 7 AND an EPERM
        // signal ("Operation not permitted") — so a no-internet runner (ENETUNREACH,
        // also exit 7) cannot make this pass vacuously; it must be a *permission*
        // denial, proving the fence (not the network) blocked it.
        let direct = run(false, "http://1.1.1.1/");
        let stderr = String::from_utf8_lossy(&direct.stderr);
        assert_eq!(
            direct.status.code(),
            Some(7),
            "direct off-box egress must be kernel-denied (curl exit 7): {stderr}"
        );
        assert!(
            stderr.contains("Operation not permitted"),
            "the block must be a kernel EPERM, not a routing failure: {stderr}"
        );

        drop(proxy);
    }

    #[test]
    fn dropping_the_handle_stops_the_listener() {
        let _serial = net_test_lock();
        let proxy = start_null(["x".to_string()], Arc::new(StdResolver)).unwrap();
        let addr = proxy.addr();
        drop(proxy);
        // After shutdown the port is no longer served: a connect either refuses
        // or the accept loop has exited. Give the OS a moment, then assert we
        // cannot complete an HTTP exchange through it.
        thread::sleep(Duration::from_millis(100));
        if let Ok(mut c) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            c.set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let _ = write!(c, "GET http://x/ HTTP/1.1\r\n\r\n");
            let mut resp = Vec::new();
            let _ = c.read_to_end(&mut resp);
            assert!(resp.is_empty(), "a stopped proxy must not serve requests");
        }
    }
}
