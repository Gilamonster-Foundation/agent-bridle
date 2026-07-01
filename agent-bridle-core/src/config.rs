//! Layered runtime configuration for the bridle (agent-bridle#141 / epic #139).
//!
//! `Caveats` is **authority** (per-invocation, rides [`crate::ToolContext`]).
//! [`BridleConfig`] is **mechanism**: the tunable knobs, limits, path lists, and
//! feature toggles that shape *how* confinement is applied — a separate channel
//! that never amplifies authority and never touches the mint chokepoint or the
//! honesty lattice (ADR 0017).
//!
//! These are pure, serde-only **types**; the file/env loader and its precedence
//! (`defaults → file → env → API`) live in the `agent-bridle-config` crate (#142).
//! Every [`Default`] here reproduces today's hard-coded constants **byte-for-byte**
//! — the anti-drift tests below assert each `Policy::default()` equals the
//! constant it mirrors (`gate.rs`, `sandbox.rs`, `rootfs.rs`), so this file can
//! never silently diverge from current behavior. Nothing consumes `BridleConfig`
//! yet (this issue is inert); wiring lands in #143–#153.

use serde::{Deserialize, Serialize};

use crate::report::AxisEnforcement;

fn to_vec(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

/// A configurable path list with **extend-by-default** semantics: `resolve()`
/// returns `base ∪ extra` unless `replace` is set, in which case only `extra` is
/// used. This lets config *widen* a security-relevant list (add a read path)
/// safely, while **shrinking** one (dropping a loader path that would break
/// confinement) requires an explicit `replace = true` opt-in. A widening is
/// surfaced via [`PathList::widens`] so it can be disclosed (never silent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathList {
    /// Built-in defaults (today's constant). Not normally set from config.
    pub base: Vec<String>,
    /// Operator additions (extend) — or the full set when `replace`.
    #[serde(default)]
    pub extra: Vec<String>,
    /// `true` ⇒ ignore `base`, use only `extra` (the shrink opt-in).
    #[serde(default)]
    pub replace: bool,
}

impl PathList {
    /// A default-backed list from a static slice (the const-mirroring constructor).
    #[must_use]
    pub fn from_defaults(base: &[&str]) -> Self {
        Self {
            base: to_vec(base),
            extra: Vec::new(),
            replace: false,
        }
    }

    /// The effective list: `base ∪ extra` (dedup, order-preserving), or `extra`
    /// alone when `replace`.
    #[must_use]
    pub fn resolve(&self) -> Vec<String> {
        if self.replace {
            return self.extra.clone();
        }
        let mut out = self.base.clone();
        for e in &self.extra {
            if !out.contains(e) {
                out.push(e.clone());
            }
        }
        out
    }

    /// `true` when the operator has *widened* the built-in list (added entries
    /// without replacing) — a disclosure-worthy loosening.
    #[must_use]
    pub fn widens(&self) -> bool {
        !self.replace && !self.extra.is_empty()
    }
}

/// The top-level confinement mode. `Bridled` (default) confines per the caveats +
/// backends; `Unbridle` is the explicit, acknowledged, honest "off" (grant
/// `Caveats::top()`, advisory floor, `SandboxKind::None`) — resolved by the loader
/// (#151), never reachable by omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BridleMode {
    /// Confine normally (the default).
    #[default]
    Bridled,
    /// No confinement — advisory only, loudly disclosed (#151).
    Unbridle,
}

/// Gate defaults (`gate.rs` constants).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatePolicy {
    /// The fence-strength floor stamped when none is set (`DEFAULT_STRENGTH_FLOOR`).
    pub default_strength_floor: AxisEnforcement,
    /// Cap on the discharge freshness-window scan (`MAX_FRESHNESS_WINDOW`).
    pub max_freshness_window: u64,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            default_strength_floor: AxisEnforcement::Advisory,
            max_freshness_window: 4096,
        }
    }
}

/// Backend availability toggles (subsumes `BRIDLE_REQUIRE_*`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendToggles {
    /// Require Landlock (fail closed if unavailable).
    #[serde(default)]
    pub require_landlock: bool,
    /// Require Seatbelt (fail closed if unavailable).
    #[serde(default)]
    pub require_seatbelt: bool,
    /// Backends to force off by name (e.g. `["seatbelt"]`).
    #[serde(default)]
    pub disable: Vec<String>,
}

/// Sandbox path lists + ABI floors (`sandbox.rs` constants).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Backend enable/require toggles.
    #[serde(default)]
    pub backends: BackendToggles,
    /// Read base when `fs_read` restricted (`BASE_READ_PATHS`).
    pub base_read_paths: PathList,
    /// Executable dirs read-allowed only when `exec` is ambient (`BIN_READ_PATHS`).
    pub bin_read_paths: PathList,
    /// Execute allow-list: the dynamic loader files only (`LOADER_PATHS`).
    pub loader_paths: PathList,
    /// Loopback identifiers for the net axis (`LOOPBACK_HOSTS`).
    pub loopback_hosts: Vec<String>,
    /// Minimum Landlock ABI (`ABI_FLOOR`).
    pub landlock_abi_floor: u32,
    /// Minimum Landlock ABI for TCP net rules (`NET_ABI_FLOOR`).
    pub landlock_net_abi_floor: u32,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            backends: BackendToggles::default(),
            base_read_paths: PathList::from_defaults(&[
                "/lib",
                "/lib64",
                "/lib32",
                "/libx32",
                "/usr/lib",
                "/usr/lib64",
                "/usr/libexec",
                "/usr/share",
                "/etc/ld.so.cache",
                "/etc/ld.so.preload",
                "/etc/alternatives",
                "/etc/nsswitch.conf",
                "/etc/localtime",
                "/etc/resolv.conf",
                "/etc/ssl",
                "/etc/ca-certificates",
                "/proc/self",
                "/dev/null",
                "/dev/zero",
                "/dev/full",
                "/dev/urandom",
                "/dev/random",
            ]),
            bin_read_paths: PathList::from_defaults(&[
                "/usr/bin",
                "/bin",
                "/usr/sbin",
                "/sbin",
                "/usr/local/bin",
                "/usr/local/sbin",
                "/opt",
            ]),
            loader_paths: PathList::from_defaults(&[
                "/lib64/ld-linux-x86-64.so.2",
                "/lib/ld-linux-x86-64.so.2",
                "/lib/ld-linux.so.2",
                "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                "/lib64/ld64.so.2",
                "/lib/ld-linux-aarch64.so.1",
                "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
                "/lib/ld-linux-armhf.so.3",
                "/lib/ld-musl-x86-64.so.1",
                "/lib/ld-musl-aarch64.so.1",
            ]),
            loopback_hosts: to_vec(&["localhost", "127.0.0.1", "::1"]),
            landlock_abi_floor: 3,
            landlock_net_abi_floor: 4,
        }
    }
}

/// Minimal-rootfs builder inputs (`rootfs.rs` constants).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootfsPolicy {
    /// Curated runtime data injected into every plan (`DATA_PATHS`).
    pub data_paths: PathList,
    /// `$PATH` fallback for bare-name program resolution (`search_dirs`).
    pub search_dirs: Vec<String>,
}

impl Default for RootfsPolicy {
    fn default() -> Self {
        Self {
            // Single source of truth: the rootfs builder reads this policy, and
            // the policy default IS the const — so the two cannot drift (I5, #144).
            data_paths: PathList::from_defaults(crate::rootfs::DATA_PATHS),
            search_dirs: to_vec(&[
                "/usr/local/bin",
                "/usr/bin",
                "/bin",
                "/usr/local/sbin",
                "/usr/sbin",
                "/sbin",
            ]),
        }
    }
}

/// Toggles for the automatic "normalizations" (assists) — each defaults to today's
/// always-on behavior; only *loosening*-safe ones are exposed as on/off (safety
/// normalizations like fs canonicalization and env-scrub are intentionally absent
/// here — see ADR 0017).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizationPolicy {
    /// Match a granted bare exec name against a program's basename (`context.rs`).
    pub exec_basename_match: bool,
    /// Resolve a dynamic program's `ldd` shared-library closure (`rootfs.rs`).
    pub ldd_closure: bool,
    /// #113 fallback: add glibc NSS modules to the closure.
    pub nss_closure_fallback: bool,
    /// #113 fallback: add the Python stdlib dirs when a `python*` is granted.
    pub python_closure_fallback: bool,
    /// Emit the missing-`.so` deny-of-function canary diagnostic (`jaild`).
    pub missing_so_canary: bool,
    /// Use the content-addressed rootfs build cache.
    pub rootfs_cache: bool,
}

impl Default for NormalizationPolicy {
    fn default() -> Self {
        Self {
            exec_basename_match: true,
            ldd_closure: true,
            nss_closure_fallback: true,
            python_closure_fallback: true,
            missing_so_canary: true,
            rootfs_cache: true,
        }
    }
}

/// Default network posture when no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetDefault {
    /// Fail-closed default (today's behavior).
    #[default]
    Deny,
    /// Allow — only meaningful under an explicit relaxed/unbridle posture.
    Allow,
}

/// How a host is matched. `#[non_exhaustive]` so REST/gRPC predicate variants
/// (#153) can be added later without breaking existing configs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HostMatch {
    /// Exact hostname (today's semantics).
    Exact(String),
    /// Domain suffix (e.g. `.example.com`).
    Suffix(String),
    /// Glob pattern.
    Glob(String),
}

/// One network rule. `#[non_exhaustive]` to admit `Rest {..}` / `Grpc {..}`
/// variants additively (#153/#153-followup).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetRule {
    /// Host-level allow (the v1 predicate; a superset of exact-host).
    Host(HostMatch),
}

/// Network policy — *refines* how the `net` authority axis (`Scope<String>`) is
/// interpreted/enforced; defaults to today's exact-host behavior (empty rules).
/// A structured rule is proxy-enforced (userspace) ⇒ the honesty report keeps a
/// non-loopback allow-list `advisory`, never `kernel` (#152).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPolicy {
    /// Posture when no rule matches.
    #[serde(default)]
    pub default: NetDefault,
    /// Ordered match rules (empty ⇒ pure `Scope<String>` exact-host behavior).
    #[serde(default)]
    pub rules: Vec<NetRule>,
}

impl Default for NetPolicy {
    fn default() -> Self {
        Self {
            default: NetDefault::Deny,
            rules: Vec::new(),
        }
    }
}

/// Shell-tool + egress-proxy limits (`shell_tool.rs` / `net_proxy.rs` constants).
/// Anti-drift tests for these land with the wiring PR (#143) where the consts live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitsPolicy {
    /// Max permitted wall-clock timeout, seconds (`MAX_TIMEOUT_SECS`).
    pub max_timeout_secs: u64,
    /// Default timeout when unspecified, seconds (`DEFAULT_TIMEOUT_SECS`).
    pub default_timeout_secs: u64,
    /// Captured stdout/stderr cap, bytes (`MAX_OUTPUT_BYTES`).
    pub max_output_bytes: usize,
    /// Env vars expandable in redirect targets (`VAR_ALLOWLIST`).
    pub var_allowlist: Vec<String>,
    /// Max glob nesting depth (`MAX_GLOB_DEPTH`).
    pub max_glob_depth: usize,
    /// Max glob matches (`MAX_GLOB_MATCHES`).
    pub max_glob_matches: usize,
    /// Proxy request-header cap, bytes (`MAX_HEAD`).
    pub proxy_max_head: usize,
    /// Proxy per-connection socket timeout, seconds (`CONN_TIMEOUT`).
    pub proxy_conn_timeout_secs: u64,
    /// Proxy bind address (loopback ephemeral).
    pub proxy_bind: String,
    /// Egress audit sink path (subsumes `BRIDLE_NET_AUDIT`); `None` = off.
    #[serde(default)]
    pub audit_sink: Option<String>,
}

impl Default for LimitsPolicy {
    fn default() -> Self {
        Self {
            max_timeout_secs: 300,
            default_timeout_secs: 60,
            max_output_bytes: 1 << 20,
            var_allowlist: to_vec(&[
                "HOME", "PWD", "OLDPWD", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "SHELL",
                "HOSTNAME", "TERM",
            ]),
            max_glob_depth: 64,
            max_glob_matches: 4096,
            proxy_max_head: 8 * 1024,
            proxy_conn_timeout_secs: 30,
            proxy_bind: "127.0.0.1:0".to_string(),
            audit_sink: None,
        }
    }
}

/// Web-fetch limits (`web_fetch.rs` constants). Anti-drift lands with wiring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebPolicy {
    /// Max redirect hops (`MAX_REDIRECTS`).
    pub max_redirects: usize,
    /// Default response body cap, bytes (`DEFAULT_MAX_BYTES`).
    pub default_max_bytes: usize,
    /// Absolute ceiling on the body cap, bytes (`HARD_MAX_BYTES`).
    pub hard_max_bytes: usize,
    /// Per-request timeout, seconds (`REQUEST_TIMEOUT_SECS`).
    pub request_timeout_secs: u64,
}

impl Default for WebPolicy {
    fn default() -> Self {
        Self {
            max_redirects: 10,
            default_max_bytes: 5 * 1024 * 1024,
            hard_max_bytes: 25 * 1024 * 1024,
            request_timeout_secs: 30,
        }
    }
}

/// Micro-VM / jail parameters (`jaild` constants). Anti-drift lands with wiring (#147).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmPolicy {
    /// Candidate qemu binaries (`QEMU_PATH`).
    pub qemu_path: Vec<String>,
    /// Guest kernel search paths (`/boot/vmlinuz`).
    pub kernel_search: Vec<String>,
    /// Guest memory, MiB (`VM_MEMORY`).
    pub memory_mb: u32,
    /// qemu accelerator spec (`accel=kvm:tcg`).
    pub accel: String,
    /// Guest kernel command line.
    pub kernel_cmdline: String,
    /// Merged-usr top-level symlinks to reproduce (`MERGED_USR_LINKS`).
    pub merged_usr_links: Vec<String>,
    /// Broker protocol max frame, bytes (`MAX_FRAME`).
    pub max_frame: usize,
    /// Broker socket path (subsumes `BRIDLE_JAILD_SOCKET`).
    #[serde(default)]
    pub jaild_socket: Option<String>,
    /// Guest-init binary path (subsumes `BRIDLE_JAIL_INIT`).
    #[serde(default)]
    pub jail_init: Option<String>,
}

impl Default for VmPolicy {
    fn default() -> Self {
        Self {
            qemu_path: to_vec(&["/usr/bin/qemu-system-x86_64"]),
            kernel_search: to_vec(&["/boot/vmlinuz"]),
            memory_mb: 512,
            accel: "kvm:tcg".to_string(),
            kernel_cmdline: "console=ttyS0 panic=1 loglevel=4".to_string(),
            merged_usr_links: to_vec(&["bin", "sbin", "lib", "lib32", "lib64", "libx32"]),
            max_frame: 64 * 1024 * 1024,
            jaild_socket: None,
            jail_init: None,
        }
    }
}

/// The complete, layered bridle configuration (mechanism). Every field defaults to
/// today's behavior; see the module docs for the authority-vs-mechanism split.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BridleConfig {
    /// Top-level confinement mode.
    pub mode: BridleMode,
    /// Gate defaults.
    pub gate: GatePolicy,
    /// Sandbox path lists + backend toggles.
    pub sandbox: SandboxPolicy,
    /// Automatic-normalization toggles.
    pub normalization: NormalizationPolicy,
    /// Minimal-rootfs builder inputs.
    pub rootfs: RootfsPolicy,
    /// Network refinement policy.
    pub net: NetPolicy,
    /// Shell + proxy limits.
    pub limits: LimitsPolicy,
    /// Web-fetch limits.
    pub web: WebPolicy,
    /// Micro-VM / jail parameters.
    pub vm: VmPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_defaults_to_bridled() {
        assert_eq!(BridleMode::default(), BridleMode::Bridled);
        assert_eq!(BridleConfig::default().mode, BridleMode::Bridled);
    }

    #[test]
    fn pathlist_extends_by_default_and_replaces_on_opt_in() {
        let mut p = PathList::from_defaults(&["/a", "/b"]);
        assert_eq!(p.resolve(), vec!["/a".to_string(), "/b".to_string()]);
        assert!(!p.widens());

        p.extra = vec!["/c".to_string(), "/a".to_string()]; // /a is a dup
        assert_eq!(
            p.resolve(),
            vec!["/a".to_string(), "/b".to_string(), "/c".to_string()],
            "extend dedups and preserves order"
        );
        assert!(p.widens(), "adding entries without replace is a widening");

        p.replace = true;
        assert_eq!(
            p.resolve(),
            vec!["/c".to_string(), "/a".to_string()],
            "replace uses only extra (the shrink opt-in)"
        );
        assert!(!p.widens(), "replace is not a widening");
    }

    #[test]
    fn gate_policy_defaults_match_constants() {
        let g = GatePolicy::default();
        assert_eq!(g.default_strength_floor, AxisEnforcement::Advisory);
        assert_eq!(g.max_freshness_window, 4096);
    }

    #[test]
    fn default_config_round_trips_through_json() {
        let c = BridleConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: BridleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn net_policy_defaults_to_deny_with_no_rules() {
        let n = NetPolicy::default();
        assert_eq!(n.default, NetDefault::Deny);
        assert!(n.rules.is_empty(), "empty rules ⇒ pure exact-host behavior");
    }

    // ── Anti-drift: defaults must equal the source constants byte-for-byte, so
    //    this inert config can never silently diverge from today's behavior. ──

    #[test]
    fn gate_defaults_match_source_constants() {
        let g = GatePolicy::default();
        assert_eq!(
            g.default_strength_floor,
            crate::gate::DEFAULT_STRENGTH_FLOOR
        );
        assert_eq!(g.max_freshness_window, crate::gate::MAX_FRESHNESS_WINDOW);
    }

    #[test]
    fn sandbox_loopback_default_matches_constant() {
        assert_eq!(
            SandboxPolicy::default().loopback_hosts,
            to_vec(crate::sandbox::LOOPBACK_HOSTS)
        );
    }

    #[cfg(all(target_os = "linux", feature = "linux-landlock"))]
    #[test]
    fn sandbox_path_defaults_match_landlock_constants() {
        use crate::sandbox::landlock_impl as l;
        assert_eq!(
            SandboxPolicy::default().base_read_paths.resolve(),
            to_vec(l::BASE_READ_PATHS)
        );
        assert_eq!(
            SandboxPolicy::default().bin_read_paths.resolve(),
            to_vec(l::BIN_READ_PATHS)
        );
        assert_eq!(
            SandboxPolicy::default().loader_paths.resolve(),
            to_vec(l::LOADER_PATHS)
        );
    }
}
