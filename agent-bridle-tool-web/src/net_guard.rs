//! The pure `net` leash: host-allowlist membership + SSRF IP screening.
//!
//! Everything here is **pure** — no network, no DNS, no [`Gate`]. That is
//! deliberate: the SSRF-defeating logic is the load-bearing security surface, so
//! it must be unit-testable in isolation (DESIGN §7). The async fetch path in
//! [`crate::web_fetch`] calls these predicates after it has done the (impure)
//! DNS resolution; the predicates themselves only ever look at an
//! already-resolved [`IpAddr`] and the granted `net` [`Scope`].
//!
//! ## The allowlist *is* the `net` Caveat
//!
//! There is no second allowlist. The effective `net` scope a tool runs under
//! (`granted.meet(required)`, minted into the [`ToolContext`]) is the allowlist:
//!
//! - `Scope::All` — every host satisfies the host check. SSRF screening still
//!   applies (an `All` grant does *not* opt every host into reaching private
//!   space), so a public fetch is fine but `All` cannot reach `127.0.0.1`.
//! - `Scope::Only({h, ...})` — only the named hosts satisfy the host check, AND
//!   a host named here is **explicitly opted in** to private-IP space. This is
//!   the single, intentional escape hatch: name `127.0.0.1` (or an internal
//!   hostname) in the grant and that host — and only that host — may resolve to
//!   a private/loopback address. Everything not named stays default-denied and
//!   SSRF-screened.
//!
//! [`Gate`]: agent_bridle_core::Gate
//! [`ToolContext`]: agent_bridle_core::ToolContext

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use agent_bridle_core::Scope;

/// Why the net guard refused a host or an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetGuardError {
    /// The host is not within the granted `net` scope (default-deny).
    HostNotAllowed {
        /// The offending host.
        host: String,
    },
    /// The host resolved to a private / loopback / link-local / unique-local
    /// address and was not explicitly opted in via the allowlist (SSRF block).
    PrivateAddress {
        /// The host that resolved to a blocked address.
        host: String,
        /// The blocked address it resolved to.
        addr: IpAddr,
    },
    /// DNS resolution yielded no usable address for the host.
    NoAddress {
        /// The host that did not resolve.
        host: String,
    },
}

impl fmt::Display for NetGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostNotAllowed { host } => {
                write!(f, "network access to {host:?} is not within the granted authority")
            }
            Self::PrivateAddress { host, addr } => write!(
                f,
                "SSRF block: {host:?} resolved to private/loopback address {addr} (not in the net allowlist)"
            ),
            Self::NoAddress { host } => write!(f, "host {host:?} did not resolve to any address"),
        }
    }
}

impl std::error::Error for NetGuardError {}

/// Is `host` *explicitly* named in the granted `net` allowlist?
///
/// This is the opt-in test for private-IP space. Only `Scope::Only` sets count:
/// an explicit grant of a host (e.g. `"127.0.0.1"` or `"internal.svc"`) opts
/// *that host* — and no other — into being allowed to resolve to a private or
/// loopback address. `Scope::All` is **not** an opt-in for private space: it
/// grants every *public* host, but does not name any host, so it returns
/// `false` here and private addresses stay blocked under `All`.
///
/// Matching is exact on the host string as it appears in the URL (the same
/// granularity [`agent_bridle_core::ToolContext::check_net`] uses), so the
/// allowlist entry and the URL host must agree literally.
#[must_use]
pub fn host_is_explicitly_allowlisted(net: &Scope<String>, host: &str) -> bool {
    match net {
        Scope::All => false,
        Scope::Only(set) => set.contains(host),
    }
}

/// Does the granted `net` scope permit reaching `host` at all (the host
/// allowlist, default-deny)?
///
/// Mirrors [`agent_bridle_core::ToolContext::check_net`]'s membership test so
/// the same decision can be made over a borrowed scope in the pure layer (e.g.
/// when re-checking a redirect target). `Scope::All` admits any host; otherwise
/// the host must be a member of the `Only` set.
#[must_use]
pub fn host_is_permitted(net: &Scope<String>, host: &str) -> bool {
    match net {
        Scope::All => true,
        Scope::Only(set) => set.contains(host),
    }
}

/// Is `ip` a private / loopback / link-local / unique-local / otherwise
/// non-public address that an SSRF attempt would target?
///
/// `true` means "block this unless the host was explicitly opted in". The
/// ranges (per DESIGN §7): IPv4 `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`,
/// `192.168.0.0/16`, `169.254.0.0/16` (link-local), `0.0.0.0/8` (this-host),
/// `100.64.0.0/10` (CGNAT), broadcast, and the IPv4 documentation/benchmark
/// ranges; IPv6 `::1` (loopback), `fc00::/7` (unique-local), `fe80::/10`
/// (link-local), the unspecified address, and IPv4-mapped/compat addresses
/// (screened by mapping back to their IPv4 form).
///
/// We implement the IPv6 predicates by hand because `Ipv6Addr::is_unique_local`
/// / `is_global` are still unstable on stable Rust; the IPv4 ones use the
/// stable `is_private` / `is_loopback` / `is_link_local` plus explicit extra
/// ranges.
#[must_use]
pub fn ip_is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_blocked(v4),
        IpAddr::V6(v6) => {
            // An IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible address is
            // really an IPv4 destination — screen it as such so it cannot be
            // used to slip a private v4 address past the v6 path.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ipv4_is_blocked(v4);
            }
            if let Some(v4) = v6.to_ipv4() {
                // `to_ipv4()` also matches the deprecated v4-compatible form.
                if v4 != Ipv4Addr::UNSPECIFIED {
                    return ipv4_is_blocked(v4);
                }
            }
            ipv6_is_blocked(v6)
        }
    }
}

/// IPv4 SSRF screen (see [`ip_is_blocked`]).
fn ipv4_is_blocked(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private()            // 10/8, 172.16/12, 192.168/16
        || ip.is_loopback()    // 127/8
        || ip.is_link_local()  // 169.254/16
        || ip.is_broadcast()   // 255.255.255.255
        || ip.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || ip.is_unspecified() // 0.0.0.0
        || o[0] == 0           // 0.0.0.0/8 "this host on this network"
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // 100.64/10 CGNAT (RFC 6598)
        || o[0] >= 240 // 240/4 reserved (incl. 255/8 broadcast space)
}

/// IPv6 SSRF screen (see [`ip_is_blocked`]).
fn ipv6_is_blocked(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true; // ::1, ::
    }
    let seg0 = ip.segments()[0];
    // fc00::/7 unique-local (matches fc00:: and fd00::).
    if (seg0 & 0xfe00) == 0xfc00 {
        return true;
    }
    // fe80::/10 link-local.
    if (seg0 & 0xffc0) == 0xfe80 {
        return true;
    }
    // ff00::/8 multicast.
    if (seg0 & 0xff00) == 0xff00 {
        return true;
    }
    false
}

/// Screen one host against the granted `net` scope and a set of resolved
/// addresses, returning the subset of addresses that are safe to connect to.
///
/// This is the single composition point the fetch path calls per hop:
///
/// 1. The host must be permitted by the scope (default-deny host allowlist).
/// 2. Each resolved address is SSRF-screened. A blocked address is dropped
///    *unless* the host is explicitly named in the allowlist (the opt-in for
///    private/loopback space — e.g. a test against `127.0.0.1`).
/// 3. At least one address must survive, or the host is refused.
///
/// Returns the surviving addresses (to pin the connection to), or a
/// [`NetGuardError`] explaining the refusal. Pure: callers do the DNS.
pub fn screen_host(
    net: &Scope<String>,
    host: &str,
    resolved: &[IpAddr],
) -> Result<Vec<IpAddr>, NetGuardError> {
    if !host_is_permitted(net, host) {
        return Err(NetGuardError::HostNotAllowed {
            host: host.to_string(),
        });
    }

    let opted_in = host_is_explicitly_allowlisted(net, host);

    let mut safe = Vec::new();
    let mut last_blocked = None;
    for &ip in resolved {
        if ip_is_blocked(ip) && !opted_in {
            last_blocked = Some(ip);
            continue;
        }
        safe.push(ip);
    }

    if safe.is_empty() {
        return match last_blocked {
            Some(addr) => Err(NetGuardError::PrivateAddress {
                host: host.to_string(),
                addr,
            }),
            None => Err(NetGuardError::NoAddress {
                host: host.to_string(),
            }),
        };
    }
    Ok(safe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // ── SSRF range coverage (per DESIGN §7) ─────────────────────────────────

    #[test]
    fn ipv4_loopback_is_blocked() {
        assert!(ip_is_blocked(ipv4(127, 0, 0, 1)));
        assert!(ip_is_blocked(ipv4(127, 255, 255, 254)));
    }

    #[test]
    fn ipv4_rfc1918_private_is_blocked() {
        assert!(ip_is_blocked(ipv4(10, 0, 0, 1)));
        assert!(ip_is_blocked(ipv4(172, 16, 5, 4)));
        assert!(ip_is_blocked(ipv4(172, 31, 255, 255)));
        assert!(ip_is_blocked(ipv4(192, 168, 1, 1)));
    }

    #[test]
    fn ipv4_link_local_169_254_is_blocked() {
        // The cloud-metadata SSRF classic.
        assert!(ip_is_blocked(ipv4(169, 254, 169, 254)));
    }

    #[test]
    fn ipv4_this_host_and_cgnat_blocked() {
        assert!(ip_is_blocked(ipv4(0, 0, 0, 0)));
        assert!(ip_is_blocked(ipv4(0, 1, 2, 3)));
        assert!(ip_is_blocked(ipv4(100, 64, 0, 1))); // CGNAT 100.64/10
        assert!(ip_is_blocked(ipv4(100, 127, 255, 255)));
    }

    #[test]
    fn ipv4_public_is_allowed() {
        assert!(!ip_is_blocked(ipv4(1, 1, 1, 1)));
        assert!(!ip_is_blocked(ipv4(8, 8, 8, 8)));
        assert!(!ip_is_blocked(ipv4(93, 184, 216, 34))); // example.com
                                                         // 100.63/x is just below CGNAT and is public.
        assert!(!ip_is_blocked(ipv4(100, 63, 255, 255)));
        // 172.15/8 and 172.32/8 are outside the 172.16/12 private block.
        assert!(!ip_is_blocked(ipv4(172, 15, 0, 1)));
        assert!(!ip_is_blocked(ipv4(172, 32, 0, 1)));
    }

    #[test]
    fn ipv6_loopback_and_ula_and_linklocal_blocked() {
        assert!(ip_is_blocked(IpAddr::V6(Ipv6Addr::LOCALHOST))); // ::1
        assert!(ip_is_blocked(IpAddr::V6(Ipv6Addr::UNSPECIFIED))); // ::
        assert!(ip_is_blocked(IpAddr::V6("fc00::1".parse().unwrap())));
        assert!(ip_is_blocked(IpAddr::V6("fd12:3456::1".parse().unwrap())));
        assert!(ip_is_blocked(IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(ip_is_blocked(IpAddr::V6("ff02::1".parse().unwrap())));
    }

    #[test]
    fn ipv6_public_is_allowed() {
        assert!(!ip_is_blocked(IpAddr::V6(
            "2606:4700:4700::1111".parse().unwrap()
        ))); // 1.1.1.1
        assert!(!ip_is_blocked(IpAddr::V6(
            "2001:4860:4860::8888".parse().unwrap()
        ))); // 8.8.8.8
    }

    #[test]
    fn ipv4_mapped_v6_private_is_blocked() {
        // ::ffff:127.0.0.1 must be screened as the loopback it really is.
        assert!(ip_is_blocked(IpAddr::V6(
            "::ffff:127.0.0.1".parse().unwrap()
        )));
        assert!(ip_is_blocked(IpAddr::V6(
            "::ffff:10.0.0.1".parse().unwrap()
        )));
        assert!(ip_is_blocked(IpAddr::V6(
            "::ffff:169.254.169.254".parse().unwrap()
        )));
        // ...and a mapped public v4 stays allowed.
        assert!(!ip_is_blocked(IpAddr::V6(
            "::ffff:8.8.8.8".parse().unwrap()
        )));
    }

    // ── Allowlist membership ────────────────────────────────────────────────

    #[test]
    fn explicit_allowlist_only_matches_named_hosts() {
        let net = Scope::only(["127.0.0.1".to_string(), "internal.svc".to_string()]);
        assert!(host_is_explicitly_allowlisted(&net, "127.0.0.1"));
        assert!(host_is_explicitly_allowlisted(&net, "internal.svc"));
        assert!(!host_is_explicitly_allowlisted(&net, "evil.test"));
        assert!(!host_is_explicitly_allowlisted(&net, "example.com"));
    }

    #[test]
    fn scope_all_is_not_an_optin_for_private_space() {
        // `All` grants every public host but names no host, so it does NOT opt
        // any host into private/loopback space.
        let net: Scope<String> = Scope::All;
        assert!(!host_is_explicitly_allowlisted(&net, "127.0.0.1"));
        assert!(host_is_permitted(&net, "anything.example"));
    }

    #[test]
    fn host_permitted_is_default_deny_under_only() {
        let net = Scope::only(["example.com".to_string()]);
        assert!(host_is_permitted(&net, "example.com"));
        assert!(!host_is_permitted(&net, "evil.test"));
    }

    // ── screen_host: the composition the fetch path uses per hop ─────────────

    #[test]
    fn screen_denies_host_not_in_scope() {
        // Only example.com is granted; 127.0.0.1 host is not even permitted.
        let net = Scope::only(["example.com".to_string()]);
        let err = screen_host(&net, "127.0.0.1", &[ipv4(127, 0, 0, 1)]).unwrap_err();
        assert!(
            matches!(err, NetGuardError::HostNotAllowed { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn screen_blocks_private_ip_for_permitted_but_not_optedin_host() {
        // `All` permits the host, but does not opt it into private space, so a
        // host that resolves to a private IP (DNS-rebinding / SSRF) is blocked.
        let net: Scope<String> = Scope::All;
        let err = screen_host(&net, "rebind.evil", &[ipv4(10, 0, 0, 5)]).unwrap_err();
        assert!(
            matches!(err, NetGuardError::PrivateAddress { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn screen_allows_loopback_only_when_host_is_explicitly_allowlisted() {
        // The deliberate opt-in: naming 127.0.0.1 in the grant lets THAT host
        // reach loopback (the test/dev escape hatch).
        let net = Scope::only(["127.0.0.1".to_string()]);
        let safe = screen_host(&net, "127.0.0.1", &[ipv4(127, 0, 0, 1)]).unwrap();
        assert_eq!(safe, vec![ipv4(127, 0, 0, 1)]);
    }

    #[test]
    fn screen_drops_blocked_addrs_keeps_safe_ones() {
        // A host that resolves to both a public and a private address (a common
        // rebinding shape): under a non-opted-in grant the private one is
        // dropped and the public one survives.
        let net: Scope<String> = Scope::All;
        let safe = screen_host(
            &net,
            "mixed.example",
            &[ipv4(10, 0, 0, 1), ipv4(8, 8, 8, 8)],
        )
        .unwrap();
        assert_eq!(safe, vec![ipv4(8, 8, 8, 8)]);
    }

    #[test]
    fn screen_no_address_errors() {
        let net: Scope<String> = Scope::All;
        let err = screen_host(&net, "ghost.example", &[]).unwrap_err();
        assert!(matches!(err, NetGuardError::NoAddress { .. }), "{err:?}");
    }
}
