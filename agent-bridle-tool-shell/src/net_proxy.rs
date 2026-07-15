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

// ── I/O seams (#166): the per-connection logic is written against `Conn` +
// `Connector` traits, not concrete `TcpStream`, so the parse / allow-list /
// forward / tunnel / audit LOGIC can be unit-tested against an in-memory duplex
// with NO real socket (deterministic, portable). Production wires the real
// `TcpStream` / `TcpConnector`; the tests wire scripted in-memory endpoints. ───

/// A bidirectional connection the proxy speaks over. Abstracts the three
/// `TcpStream`-specific operations the forward/tunnel path needs beyond
/// `Read`/`Write` — a second owned handle ([`Self::dup`], for the read/write
/// split and the origin clone), directional [`Self::shutdown`] (how the copy
/// threads signal EOF), and the per-connection timeouts ([`Self::set_timeouts`]).
/// `TcpStream` implements it for production; an in-memory scripted stream
/// implements it for tests.
pub trait Conn: Read + Write + Send {
    /// A second owned handle to the SAME underlying stream — for `TcpStream`
    /// this is `try_clone` (both handles share one socket); the proxy holds one
    /// half for reading and one for writing, and `splice` needs a third for the
    /// origin write direction.
    fn dup(&self) -> io::Result<Box<dyn Conn>>;
    /// Shut down the read half, write half, or both — how a copy thread signals
    /// EOF to its peer and how a response closes the client.
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
    /// Apply the per-connection read+write timeouts. A no-op for in-memory
    /// fakes, which never block on a real socket.
    fn set_timeouts(&self, dur: Duration) -> io::Result<()>;
}

impl Conn for TcpStream {
    fn dup(&self) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(self.try_clone()?))
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }
    fn set_timeouts(&self, dur: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(dur))?;
        self.set_write_timeout(Some(dur))?;
        Ok(())
    }
}

/// Dials a resolved origin, returning the connection to forward to. A seam so a
/// test can hand the proxy a scripted in-memory origin instead of a real TCP
/// dial — the second half (with [`Conn`]) of what makes the forward path
/// testable without a socket.
pub trait Connector: Send + Sync {
    /// Connect to `addr`, or fail (surfaced to the client as `502 Bad Gateway`).
    fn connect(&self, addr: SocketAddr) -> io::Result<Box<dyn Conn>>;
}

/// The production connector — a real bounded TCP dial to the resolved origin.
pub struct TcpConnector;

impl Connector for TcpConnector {
    fn connect(&self, addr: SocketAddr) -> io::Result<Box<dyn Conn>> {
        let s = TcpStream::connect_timeout(&addr, CONN_TIMEOUT)?;
        s.set_read_timeout(Some(CONN_TIMEOUT))?;
        s.set_write_timeout(Some(CONN_TIMEOUT))?;
        Ok(Box::new(s))
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
    /// #196: out-of-allow-list hosts the child tried to reach — refused with 403.
    /// Accumulated across all connections (independent of the opt-in audit sink)
    /// so the shell tool can surface them as structured `net` denials.
    refused: Arc<Mutex<HashSet<String>>>,
}

impl ProxyHandle {
    /// The loopback address the fenced child is pointed at. Only tests read it
    /// directly; production wires the child via [`Self::proxy_env`].
    #[cfg(test)]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// #196: the CONNECT hosts this proxy REFUSED (not on the allow-list),
    /// deduplicated and sorted. The shell tool reads this after the child is
    /// reaped and turns each into a `Denial { kind: Net, target: host }` so a
    /// consumer can prompt per-host. Empty when the child only reached
    /// allow-listed hosts (or none).
    #[must_use]
    pub fn refused_hosts(&self) -> Vec<String> {
        self.refused
            .lock()
            .map(|s| {
                let mut v: Vec<String> = s.iter().cloned().collect();
                v.sort();
                v
            })
            .unwrap_or_default()
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
    // The production origin dialer — a real TCP connect. Tests bypass `start`
    // entirely and drive `handle_conn` with a scripted in-memory connector.
    let connector: Arc<dyn Connector> = Arc::new(TcpConnector);
    // #196: shared refused-host accumulator, populated by each connection thread.
    let refused: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    let accept = {
        let shutdown = Arc::clone(&shutdown);
        let refused = Arc::clone(&refused);
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
                    let connector = Arc::clone(&connector);
                    let sink = Arc::clone(&sink);
                    let refused = Arc::clone(&refused);
                    // One detached thread per connection; it ends at EOF.
                    let _ = thread::Builder::new()
                        .name("agent-bridle-egress-conn".to_string())
                        .spawn(move || {
                            let _ = handle_conn(
                                Box::new(client),
                                &policy,
                                connector.as_ref(),
                                resolver.as_ref(),
                                sink.as_ref(),
                                &refused,
                            );
                        });
                }
            })?
    };

    Ok(ProxyHandle {
        addr,
        shutdown,
        accept: Some(accept),
        refused,
    })
}

/// Serve one client connection: parse its request line, enforce the allow-list,
/// and either tunnel (`CONNECT`) or forward (`http://`) to the resolved origin.
/// Every connection with a parsed host is recorded through `sink`.
fn handle_conn(
    client: Box<dyn Conn>,
    policy: &HostPolicy,
    connector: &dyn Connector,
    resolver: &dyn Resolver,
    sink: &dyn AuditSink,
    refused: &Mutex<HashSet<String>>,
) -> io::Result<()> {
    client.set_timeouts(CONN_TIMEOUT)?;
    let mut reader = BufReader::new(client.dup()?);
    let t0 = Instant::now();

    let line = read_line_bounded(&mut reader)?;
    let Some(target) = parse_request_line(&line) else {
        // No host to attribute — a malformed request is not an egress event.
        return respond(client.as_ref(), 400, "Bad Request");
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
                                          // #196: record the refused host so the shell tool can surface it as a
                                          // structured `net` denial (the audit sink is opt-in; this is always on).
        if let Ok(mut set) = refused.lock() {
            set.insert(host.clone());
        }
        return respond(client.as_ref(), 403, "Forbidden");
    }

    match target {
        Target::Connect { host, port } => {
            // CONNECT: drain the remaining request headers (up to the blank line)
            // before the tunnel begins — the client waits for our 200 first.
            drain_headers(&mut reader)?;
            let origin = match resolver
                .resolve(&host, port)
                .and_then(guard_target)
                .and_then(|addr| connector.connect(addr))
            {
                Ok(o) => o,
                Err(_) => {
                    audit(NetDecision::Error, 0, 0);
                    return respond(client.as_ref(), 502, "Bad Gateway");
                }
            };
            // A CONNECT success is a *bare* status line — no body, no
            // `Content-Length` — after which the socket is an opaque tunnel. (Do
            // NOT use `respond`, which appends a body that would corrupt it.)
            let mut client = client;
            client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
            // Forward via `splice_buffered` (not a raw `tunnel`) so any bytes the
            // client already pipelined past the CONNECT header block — buffered in
            // `reader` — reach the origin (a TLS ClientHello sent with the CONNECT;
            // #138). The up-copy reads the BufReader, which drains its buffer first.
            let (up, down) = splice_buffered(reader, client, origin)?;
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
            let mut origin = match resolver
                .resolve(&host, port)
                .and_then(guard_target)
                .and_then(|addr| connector.connect(addr))
            {
                Ok(o) => o,
                Err(_) => {
                    audit(NetDecision::Error, 0, 0);
                    return respond(client.as_ref(), 502, "Bad Gateway");
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

/// Read one CRLF-terminated line, bounded to [`MAX_HEAD`]. Generic over the
/// buffered reader's source so the same logic drives a real socket or an
/// in-memory test stream.
fn read_line_bounded<R: Read>(reader: &mut BufReader<R>) -> io::Result<String> {
    let mut buf = Vec::new();
    reader.take(MAX_HEAD as u64).read_until(b'\n', &mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Read request header lines up to (not including) the terminating blank line,
/// bounded by [`MAX_HEAD`]. Each returned line keeps its trailing CRLF.
fn read_headers<R: Read>(reader: &mut BufReader<R>) -> io::Result<Vec<String>> {
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
fn drain_headers<R: Read>(reader: &mut BufReader<R>) -> io::Result<()> {
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
fn respond(client: &dyn Conn, code: u16, reason: &str) -> io::Result<()> {
    let mut c = client.dup()?;
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
/// SSRF-pivot guard (#138): refuse to dial a resolved origin whose IP is on an
/// **internal** range — RFC1918 private, `169.254/16` link-local (incl. the cloud
/// metadata endpoint `169.254.169.254`), `100.64/10` CGNAT, and IPv6 ULA/link-local.
/// The egress proxy fronts a *loopback-fenced* child; without this an allow-listed
/// name that resolves (or is rebound) to an internal address would give that child
/// a parent-mediated path to endpoints its own kernel fence forbids. Loopback is
/// **allowed** (the fenced child can already reach loopback directly, and the test
/// origins live there) and global addresses are allowed.
///
/// Default-on and unconditional today; a `NetPolicy` opt-out is future work (I13,
/// #152). Returns the address unchanged when permitted, else `PermissionDenied`.
fn guard_target(addr: SocketAddr) -> io::Result<SocketAddr> {
    if is_internal_ip(&addr.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SSRF-guard: refusing to proxy to an internal (non-loopback) address",
        ));
    }
    Ok(addr)
}

/// `true` if `ip` is on a private/internal range the egress proxy must not pivot
/// to (see [`guard_target`]). Loopback and global addresses return `false`.
fn is_internal_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // 100.64.0.0/10 (CGNAT) — not covered by the std predicates.
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        std::net::IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_unspecified()
                || (seg0 & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (seg0 & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

/// Like [`tunnel`] but the client side is a `BufReader` that may already hold
/// buffered bytes (the `http://` forward case, after the request line was read).
/// Returns `(bytes_up, bytes_down)` for the audit.
fn splice_buffered(
    mut client_reader: BufReader<Box<dyn Conn>>,
    client: Box<dyn Conn>,
    origin: Box<dyn Conn>,
) -> io::Result<(u64, u64)> {
    let mut o_write = origin.dup()?;
    let up = thread::spawn(move || {
        let n = copy_counted(&mut client_reader, &mut o_write);
        let _ = o_write.shutdown(Shutdown::Write);
        n
    });
    let mut o_read = origin;
    let mut c_write = client;
    let down = copy_counted(&mut o_read, &mut c_write);
    // The origin side has closed, so tear the whole connection down: shut down
    // BOTH client halves, not just write. `Write` alone leaves the `up` thread
    // blocked reading the client's (half-open) upload direction until CONN_TIMEOUT
    // — a plain client that sends its request then only reads the response never
    // closes its write half until it sees our EOF, and we never see its EOF: a
    // ~30s deadlock on every forward/tunnel (surfaced by the flaky `audit_records_*`
    // test, since the audit fires only once `up` joins). `Both` gives `up`'s read
    // on the shared socket an immediate EOF.
    let _ = c_write.shutdown(Shutdown::Both);
    let up = up.join().unwrap_or(0);
    Ok((up, down))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// #138 (SSRF pivot): the proxy must refuse to dial an allow-listed name that
    /// resolves to an internal address (RFC1918 / link-local incl. cloud metadata /
    /// CGNAT / IPv6 ULA+link-local), while permitting loopback (the fenced child can
    /// reach it directly + the test origins live there) and global addresses.
    #[test]
    fn guard_target_refuses_internal_permits_loopback_and_global() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        // Built from octets (not dotted-string literals) so the internal-specifics
        // linter doesn't flag the RFC1918/CGNAT probe addresses (docs/PRIVACY.md).
        let refused: [IpAddr; 7] = [
            Ipv4Addr::new(10, 0, 0, 5).into(),        // RFC1918
            Ipv4Addr::new(172, 16, 9, 9).into(),      // RFC1918
            Ipv4Addr::new(192, 168, 1, 1).into(),     // RFC1918
            Ipv4Addr::new(169, 254, 169, 254).into(), // link-local: cloud metadata
            Ipv4Addr::new(100, 64, 0, 1).into(),      // CGNAT
            "fe80::1".parse().unwrap(),               // v6 link-local
            "fc00::1".parse().unwrap(),               // v6 unique-local
        ];
        for ip in refused {
            assert!(is_internal_ip(&ip), "{ip} must classify as internal");
            assert!(
                guard_target(SocketAddr::new(ip, 80)).is_err(),
                "{ip} must be refused"
            );
        }
        let allowed = [
            "127.0.0.1",
            "::1",
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
        ];
        for s in allowed {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_internal_ip(&ip), "{s} must be permitted");
            assert!(
                guard_target(SocketAddr::new(ip, 443)).is_ok(),
                "{s} must be permitted"
            );
        }
    }

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

    // ── In-memory connection fakes (#166) ───────────────────────────────────
    //
    // The proxy's forward/tunnel/allow-list/audit LOGIC is driven through the
    // real `handle_conn` against these scripted endpoints — no sockets, no
    // accept loops, no timing races. `handle_conn` joins its splice thread
    // before returning, so every assertion below is fully synchronous and
    // deterministic (the old socket tests polled/slept up to 30s and still
    // flaked on constrained runners; #135/#155/#165/#166).

    /// A scripted in-memory [`Conn`]: `read` drains a preset script then returns
    /// EOF (never blocks); `write` captures bytes for assertions; `dup` shares
    /// both (as `TcpStream::try_clone` shares one socket). `shutdown`/timeouts
    /// are no-ops — the fake EOFs on script exhaustion, so nothing can block.
    #[derive(Clone, Default)]
    struct ScriptedConn {
        /// Bytes the proxy reads FROM this endpoint (the client's request, or the
        /// origin's canned response). Drained by `read`; empty ⇒ EOF.
        to_read: Arc<Mutex<VecDeque<u8>>>,
        /// Bytes the proxy WROTE to this endpoint (its client response, or the
        /// request it forwarded to the origin). Captured for assertions.
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl ScriptedConn {
        fn with_script(bytes: &[u8]) -> Self {
            Self {
                to_read: Arc::new(Mutex::new(bytes.iter().copied().collect())),
                written: Arc::new(Mutex::new(Vec::new())),
            }
        }
        /// The bytes the proxy wrote to this endpoint.
        fn written(&self) -> Vec<u8> {
            self.written.lock().unwrap().clone()
        }
        /// The bytes the proxy wrote, as a lossy string (for readable asserts).
        fn written_str(&self) -> String {
            String::from_utf8_lossy(&self.written()).into_owned()
        }
    }

    impl Read for ScriptedConn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut q = self.to_read.lock().unwrap();
            let n = buf.len().min(q.len());
            for slot in buf.iter_mut().take(n) {
                *slot = q.pop_front().unwrap();
            }
            Ok(n) // n == 0 ⇒ script exhausted ⇒ EOF (never blocks)
        }
    }

    impl Write for ScriptedConn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Conn for ScriptedConn {
        fn dup(&self) -> io::Result<Box<dyn Conn>> {
            Ok(Box::new(self.clone()))
        }
        fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
            Ok(())
        }
        fn set_timeouts(&self, _dur: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    /// A connector that hands back a scripted in-memory origin (no real dial).
    struct FakeConnector(ScriptedConn);
    impl Connector for FakeConnector {
        fn connect(&self, _addr: SocketAddr) -> io::Result<Box<dyn Conn>> {
            Ok(Box::new(self.0.clone()))
        }
    }

    /// A connector whose dial always fails — for the `502 Bad Gateway` path.
    struct FailingConnector;
    impl Connector for FailingConnector {
        fn connect(&self, _addr: SocketAddr) -> io::Result<Box<dyn Conn>> {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "origin unreachable",
            ))
        }
    }

    /// The outcome of driving one connection through the real `handle_conn`.
    struct Driven {
        /// What the proxy sent back to the client (response / forwarded origin bytes).
        client: ScriptedConn,
        /// What the proxy forwarded to the origin (empty if it was never dialled).
        origin: ScriptedConn,
        /// Hosts refused with 403 (deduped, sorted).
        refused: Vec<String>,
        /// Audit events emitted (synchronously, before `handle_conn` returned).
        audit: Vec<NetAuditEvent>,
    }

    /// Drive one client `request` through `handle_conn` with `connector` (used
    /// for the deny / malformed / 502 paths, where the origin is never
    /// successfully forwarded to — `out.origin` stays empty). Deterministic:
    /// `handle_conn` joins its splice thread before returning, so all buffers +
    /// the audit are fully populated on return. For the ALLOWED forward path
    /// (where you want to inspect the forwarded bytes) use [`drive_forward`].
    fn drive_with(request: &[u8], allow: &[&str], connector: &dyn Connector) -> Driven {
        let client = ScriptedConn::with_script(request);
        let policy = HostPolicy::new(allow.iter().map(|s| s.to_string()));
        let resolver = FixedResolver("127.0.0.1:9".parse().unwrap());
        let sink = CapturingSink::default();
        let refused = Mutex::new(HashSet::new());
        let _ = handle_conn(
            Box::new(client.clone()),
            &policy,
            connector,
            &resolver,
            &sink,
            &refused,
        );
        let mut refused: Vec<String> = refused.into_inner().unwrap().into_iter().collect();
        refused.sort();
        Driven {
            client,
            origin: ScriptedConn::default(),
            refused,
            audit: sink.events(),
        }
    }

    /// Convenience: drive an ALLOWED forward/tunnel with an explicit origin
    /// script, returning the `Driven` outcome (with the origin's captured bytes).
    fn drive_forward(request: &[u8], allow: &[&str], origin_script: &[u8]) -> Driven {
        let client = ScriptedConn::with_script(request);
        let origin = ScriptedConn::with_script(origin_script);
        let policy = HostPolicy::new(allow.iter().map(|s| s.to_string()));
        let resolver = FixedResolver("127.0.0.1:9".parse().unwrap());
        let sink = CapturingSink::default();
        let refused = Mutex::new(HashSet::new());
        let connector = FakeConnector(origin.clone());
        let _ = handle_conn(
            Box::new(client.clone()),
            &policy,
            &connector,
            &resolver,
            &sink,
            &refused,
        );
        let mut refused: Vec<String> = refused.into_inner().unwrap().into_iter().collect();
        refused.sort();
        Driven {
            client,
            origin,
            refused,
            audit: sink.events(),
        }
    }

    #[test]
    fn allowed_http_host_is_forwarded_to_origin() {
        // The allow-listed host is forwarded; the origin's body reaches the client.
        let out = drive_forward(
            b"GET http://allowed.test/x HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\r\n",
            &["allowed.test"],
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin",
        );
        let client_saw = out.client.written_str();
        assert!(client_saw.contains("200"), "client saw: {client_saw}");
        assert!(
            client_saw.contains("origin"),
            "the origin's body must reach the client: {client_saw}"
        );
        // The request reached the origin (proof the forward actually happened).
        assert!(
            out.origin.written_str().starts_with("GET /x HTTP/1.1"),
            "origin must receive the origin-form request: {}",
            out.origin.written_str()
        );
        assert!(out.refused.is_empty(), "an allowed host is not refused");
    }

    #[test]
    fn disallowed_http_host_is_refused_403_without_reaching_origin() {
        // A denied host must never be dialled: FailingConnector would surface as a
        // 502 if it were ever called, so a 403 here also proves it was NOT.
        let out = drive_with(
            b"GET http://evil.test/x HTTP/1.1\r\nHost: ignored\r\n\r\n",
            &["allowed.test"],
            &FailingConnector,
        );
        let client_saw = out.client.written_str();
        assert!(
            client_saw.contains("403"),
            "denied host must get 403: {client_saw}"
        );
        assert!(
            !client_saw.contains("502"),
            "the origin must not be dialled for a denied host: {client_saw}"
        );
        assert!(out.origin.written().is_empty(), "origin must see nothing");
    }

    #[test]
    fn unreachable_allowed_origin_yields_502() {
        // Allow-listed, but the dial fails → 502 Bad Gateway + an `Error` audit.
        let out = drive_with(
            b"GET http://allowed.test/x HTTP/1.1\r\nHost: ignored\r\n\r\n",
            &["allowed.test"],
            &FailingConnector,
        );
        assert!(
            out.client.written_str().contains("502"),
            "an unreachable allowed origin must get 502: {}",
            out.client.written_str()
        );
        let ev = out.audit.iter().find(|e| e.host == "allowed.test").unwrap();
        assert_eq!(ev.decision, NetDecision::Error);
    }

    #[test]
    fn malformed_request_yields_400_and_no_audit() {
        // A request line the proxy does not speak → 400, and (deliberately) NO
        // audit event, since there is no host to attribute an egress attempt to.
        let out = drive_with(
            b"GET / HTTP/1.1\r\n\r\n",
            &["allowed.test"],
            &FailingConnector,
        );
        assert!(out.client.written_str().contains("400"));
        assert!(
            out.audit.is_empty(),
            "a malformed request is not an egress event: {:?}",
            out.audit
        );
        assert!(out.refused.is_empty());
    }

    /// #196: the proxy accumulates every host it REFUSES and surfaces them via
    /// `refused_hosts()` (deduped, sorted); allowed hosts are never listed.
    #[test]
    fn refused_hosts_surfaces_denied_hosts_deduped_and_omits_allowed() {
        // Drive three requests through ONE shared refused-set: allowed (forwarded),
        // then the same denied host twice (must dedupe to a single entry).
        let policy = HostPolicy::new(["allowed.test".to_string()]);
        let resolver = FixedResolver("127.0.0.1:9".parse().unwrap());
        let sink = NullSink;
        let refused = Mutex::new(HashSet::new());
        let origin = ScriptedConn::with_script(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let connector = FakeConnector(origin);

        for (req, conn) in [
            (
                &b"GET http://allowed.test/x HTTP/1.1\r\nHost: a\r\n\r\n"[..],
                &connector as &dyn Connector,
            ),
            (
                &b"GET http://evil.test/y HTTP/1.1\r\nHost: a\r\n\r\n"[..],
                &FailingConnector,
            ),
            (
                &b"GET http://evil.test/z HTTP/1.1\r\nHost: a\r\n\r\n"[..],
                &FailingConnector,
            ),
        ] {
            let client = ScriptedConn::with_script(req);
            let _ = handle_conn(Box::new(client), &policy, conn, &resolver, &sink, &refused);
        }

        let mut got: Vec<String> = refused.into_inner().unwrap().into_iter().collect();
        got.sort();
        assert_eq!(
            got,
            vec!["evil.test".to_string()],
            "only the denied host, deduped; the allowed host must NOT appear: {got:?}"
        );
    }

    #[test]
    fn audit_records_allowed_with_bytes_and_denied_attempts() {
        // Allowed forward: an `Allowed` Http event on port 80 with response bytes.
        let allowed = drive_forward(
            b"GET http://allowed.test/x HTTP/1.1\r\nHost: ignored\r\n\r\n",
            &["allowed.test"],
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin",
        );
        let ev = allowed
            .audit
            .iter()
            .find(|e| e.host == "allowed.test")
            .expect("an allowed event");
        assert_eq!(ev.decision, NetDecision::Allowed);
        assert_eq!(ev.kind, NetKind::Http);
        assert_eq!(ev.port, 80);
        assert!(
            ev.bytes_down > 0,
            "an allowed connection records response bytes: {ev:?}"
        );

        // Denied: a `Denied` event (the exfil-attempt signal) with zero bytes.
        let denied = drive_with(
            b"GET http://evil.test/y HTTP/1.1\r\nHost: ignored\r\n\r\n",
            &["allowed.test"],
            &FailingConnector,
        );
        let ev = denied
            .audit
            .iter()
            .find(|e| e.host == "evil.test")
            .expect("a denied event");
        assert_eq!(ev.decision, NetDecision::Denied);
        assert_eq!(ev.bytes_up, 0);
        assert_eq!(ev.bytes_down, 0);
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

    #[test]
    fn connect_allowed_host_tunnels_opaque_bytes() {
        // The client pipelines "PING" right after the CONNECT header block; the
        // (scripted) origin returns "PING" as its side of the opaque exchange.
        // Proof of a real bidirectional tunnel: the origin receives the client's
        // PING (up-copy) and the client receives the origin's PING (down-copy),
        // after a bare 200 status line — driven through the real splice logic.
        let out = drive_forward(
            b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\nPING",
            &["allowed.test"],
            b"PING",
        );
        let client_saw = out.client.written_str();
        assert!(
            client_saw.starts_with("HTTP/1.1 200"),
            "CONNECT must be accepted with a bare 200: {client_saw:?}"
        );
        assert!(
            client_saw.contains("PING"),
            "the origin's bytes must tunnel back to the client: {client_saw:?}"
        );
        assert_eq!(
            out.origin.written(),
            b"PING",
            "the client's pipelined bytes must reach the origin through the tunnel"
        );
    }

    #[test]
    fn connect_disallowed_host_is_refused_403() {
        let out = drive_with(
            b"CONNECT evil.test:443 HTTP/1.1\r\n\r\n",
            &["allowed.test"],
            &FailingConnector,
        );
        assert!(
            out.client.written_str().contains("403"),
            "a denied CONNECT must get 403, not a tunnel: {}",
            out.client.written_str()
        );
    }

    #[test]
    fn http_host_header_is_normalized_to_the_validated_authority() {
        // The authority (allowed.test) is validated, but the client LIES with a
        // spoofed `Host: evil.test` to domain-front. The origin must see the
        // validated authority substituted in, never the spoof.
        let out = drive_forward(
            b"GET http://allowed.test/ HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n",
            &["allowed.test"],
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let origin_saw = out.origin.written_str();
        assert!(
            origin_saw.contains("Host: allowed.test\r\n"),
            "origin must receive the validated Host: {origin_saw:?}"
        );
        assert!(
            !origin_saw.contains("evil.test"),
            "the spoofed Host must not reach the origin: {origin_saw:?}"
        );
    }

    /// Serialize the tests that touch REAL loopback sockets (#155, #207). They
    /// share the host's loopback and ephemeral-port space, so concurrent
    /// siblings can interfere — e.g. a port released by one test can be
    /// re-bound by a sibling before the first is done probing it, and the
    /// probe then observes the sibling's live listener. One shared lock
    /// removes that interference class wholesale; the motivating (never
    /// locally reproduced) flake was `Empty reply from server` on the
    /// fenced_child test in PR #195's macOS CI. The in-memory tests above
    /// (#216) need no lock — only the real-socket tests below take it.
    /// Process-local, which suffices because `cargo test` runs test binaries
    /// sequentially; a per-test-process runner (e.g. nextest) would NOT be
    /// covered, nor would the loopback binds in other crates' test binaries.
    /// Poison is ignored so a panicking test does not cascade-fail the rest.
    fn net_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn proxy_env_points_at_the_bound_loopback_addr() {
        // A REAL-socket test: `proxy_env` is derived from the actually-bound
        // loopback address, so this exercises the real `bind` — and its live
        // accept-loop listener must not interleave with the port probes of the
        // sibling real-socket tests.
        let _serial = net_test_lock();
        let proxy = start_null(["x".to_string()], Arc::new(StdResolver)).unwrap();
        let env = proxy.proxy_env();
        let url = format!("http://127.0.0.1:{}", proxy.addr().port());
        assert!(env.iter().any(|(k, v)| k == "https_proxy" && *v == url));
        assert!(env.iter().any(|(k, v)| k == "HTTPS_PROXY" && *v == url));
        assert!(env.iter().all(|(_, v)| v.starts_with("http://127.0.0.1:")));
    }

    /// A one-shot HTTP origin on loopback that replies 200 with a marker body —
    /// used ONLY by the macOS kernel e2e below, which must drive real `curl`
    /// through the real proxy over a real socket (the in-memory fakes cannot
    /// exercise a kernel fence). Gated to that test's platform so it is not dead
    /// code elsewhere.
    #[cfg(all(target_os = "macos", feature = "macos-seatbelt"))]
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

    /// End-to-end kernel proof (#124, ADR 0016): a real `curl` child, confined by
    /// the ADR 0015 loopback fence, reaches an ALLOWED host only through the proxy
    /// (200), is refused a DENIED host by the proxy (403), and — crucially —
    /// **cannot bypass** the proxy: a direct off-box connect is kernel-denied. All
    /// hermetic — the resolver maps the allow-listed name to a loopback origin, so
    /// no real network is touched. macOS + `macos-seatbelt` only; self-skips if
    /// `sandbox-exec`/`curl` are unavailable. This is the one test that genuinely
    /// needs the real socket path (the fence is a kernel property); the forward /
    /// tunnel / allow-list / audit LOGIC is covered deterministically in-memory
    /// above.
    #[cfg(all(target_os = "macos", feature = "macos-seatbelt"))]
    #[test]
    fn fenced_child_reaches_allowed_via_proxy_denied_refused_direct_kernel_blocked() {
        use agent_bridle_core::{
            best_available_sandbox, loopback_fenced_caveats, seatbelt_is_supported, Caveats,
            SandboxPolicy, Scope,
        };
        // Serialize with sibling loopback tests (issue #207): this is the
        // heaviest net test (origin + proxy + real curl child) and must not
        // race siblings on loopback. Held for the whole test via RAII.
        let _serial = net_test_lock();
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
        let prefix = best_available_sandbox(&Arc::new(SandboxPolicy::default()))
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

    /// The other always-on REAL-socket test: it must exercise the actual
    /// `TcpListener` bind + accept loop + `Drop` teardown, which no in-memory
    /// fake can. It probes a just-released ephemeral port, so it serializes on
    /// `net_test_lock()` — a concurrent sibling could re-bind that port between
    /// the drop and the probe, and the probe would then hit the sibling's live
    /// listener (#207).
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
