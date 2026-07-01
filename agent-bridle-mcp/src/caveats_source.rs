//! Sourcing the session's **granted** [`Caveats`] — the leash this MCP server
//! confines every `tools/call` to.
//!
//! This is the whole point of running the registry behind MCP: the server is
//! only as confined as the grant it loads. Resolution order (first hit wins):
//!
//! 1. **`$AGENT_BRIDLE_CAVEATS`** — a JSON document using the agent-mesh
//!    [`Caveats`] serde shape. Lets an orchestrator mint a per-session leash
//!    inline (e.g. the Desk handing a worker an attenuated grant).
//! 2. **`~/.agent-bridle/config.toml`**, table **`[caveats]`** — a persistent
//!    per-host default, same field/enum shape expressed in TOML.
//! 3. **Default: DENY-ALL (fail-closed).** No grant configured ⇒ no authority on
//!    any axis. This is the red-team §9.3 fix: the bridle exists to *confine*, so
//!    a missing grant must mean "nothing," never `top()` ("everything"). An
//!    operator grants authority by setting source 1 or 2; absence is safe.
//!
//! The TOML/JSON shapes are identical to the Rust `Caveats` serde derive:
//! string axes are either `"all"` or `{ "only": [..] }`; `max_calls` is either
//! `"unlimited"` or `{ "at_most": N }`. See the crate README for full examples.

use std::path::{Path, PathBuf};

use agent_bridle::{Caveats, CountBound, Scope};

/// Environment variable carrying an inline JSON grant.
const ENV_CAVEATS: &str = "AGENT_BRIDLE_CAVEATS";

/// The bridle **mode** intent (ADR 0018): `unbridle` requests the escape hatch.
const ENV_MODE: &str = "BRIDLE_MODE";
/// The unbridle **acknowledgement** — the second key (ADR 0018 D3).
const ENV_UNBRIDLE_ACK: &str = "AGENT_BRIDLE_UNBRIDLE";
/// The exact ack token: long and self-describing so it can't be set by muscle
/// memory or pasted without reading it (ADR 0018 D3).
const UNBRIDLE_ACK_TOKEN: &str = "i-understand-this-is-dangerous";

/// The fail-closed bottom: no authority on any axis. The dual of `Caveats::top()`
/// — used as the default when no grant is configured (§9.3). `agent-mesh-protocol`
/// ships `top()` but no lattice bottom yet; constructed here until it does.
fn deny_all() -> Caveats {
    Caveats {
        fs_read: Scope::none(),
        fs_write: Scope::none(),
        exec: Scope::none(),
        net: Scope::none(),
        max_calls: CountBound::AtMost(0),
        valid_for_generation: Scope::none(),
    }
}

/// Where the granted leash came from — surfaced in the startup banner so an
/// operator can see, at a glance, whether the server is confined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaveatsSource {
    /// Loaded from the `AGENT_BRIDLE_CAVEATS` environment variable (JSON).
    Env,
    /// Loaded from `~/.agent-bridle/config.toml` `[caveats]`.
    ConfigFile(PathBuf),
    /// No grant configured — defaulted to DENY-ALL (fail-closed, §9.3).
    FailClosedDefault,
    /// **Unbridled** (ADR 0018): the two-key escape hatch engaged. The configured
    /// grant is kept (never widened); the L3 confinement mechanism is off. `ack` is
    /// the acknowledgement token the operator supplied, recorded for the audit trail.
    Unbridled { ack: String },
    /// `BRIDLE_MODE=unbridle` was requested **without** the required ack — refused
    /// and failed closed to DENY-ALL (never a silent unbridle, ADR 0018 D3).
    UnbridleRefused { reason: String },
}

/// The resolved leash plus where it came from.
#[derive(Debug)]
pub struct GrantedCaveats {
    /// The granted authority every dispatch is confined to.
    pub caveats: Caveats,
    /// Provenance of `caveats`, for the startup banner.
    pub source: CaveatsSource,
}

impl GrantedCaveats {
    /// Resolve the granted leash from the environment / config / default,
    /// using the real `$HOME`.
    ///
    /// # Errors
    /// Returns an error only when a *present* source is malformed (bad JSON in
    /// `$AGENT_BRIDLE_CAVEATS`, or an unparsable `[caveats]` table) — a missing
    /// source is not an error, it falls through to the next.
    pub fn load() -> anyhow::Result<Self> {
        let env = std::env::var(ENV_CAVEATS).ok();
        let home = home_dir();
        let base = Self::resolve(env.as_deref(), home.as_deref())?;
        let mode = std::env::var(ENV_MODE).ok();
        let ack = std::env::var(ENV_UNBRIDLE_ACK).ok();
        Ok(Self::apply_unbridle(base, mode.as_deref(), ack.as_deref()))
    }

    /// Apply the ADR 0018 unbridle escape hatch on top of a resolved grant.
    ///
    /// Unbridle needs **both** keys: `BRIDLE_MODE=unbridle` **and**
    /// `AGENT_BRIDLE_UNBRIDLE=i-understand-this-is-dangerous`. With both, the
    /// configured grant is **kept unchanged** (never widened to `top()` — authority
    /// is untouched; only the mechanism is dropped, ADR 0018 D1) and the source is
    /// stamped [`CaveatsSource::Unbridled`]; the caller must then flip the core
    /// process marker ([`agent_bridle::set_unbridled`]). With the mode set but the
    /// ack missing/wrong, it **fails closed** to DENY-ALL with an
    /// [`CaveatsSource::UnbridleRefused`] provenance — never a silent unbridle.
    /// Neither key alone does anything. Pure/testable.
    #[must_use]
    pub fn apply_unbridle(base: Self, mode: Option<&str>, ack: Option<&str>) -> Self {
        if mode.map(|m| m.trim().to_ascii_lowercase()).as_deref() != Some("unbridle") {
            return base; // not requested — leave the resolved grant as-is
        }
        if ack == Some(UNBRIDLE_ACK_TOKEN) {
            Self {
                caveats: base.caveats, // KEEP the configured grant (not top())
                source: CaveatsSource::Unbridled {
                    ack: UNBRIDLE_ACK_TOKEN.to_string(),
                },
            }
        } else {
            Self {
                caveats: deny_all(),
                source: CaveatsSource::UnbridleRefused {
                    reason: format!(
                        "{ENV_MODE}=unbridle requires {ENV_UNBRIDLE_ACK}={UNBRIDLE_ACK_TOKEN}"
                    ),
                },
            }
        }
    }

    /// Whether this resolution engaged the unbridle escape hatch — the caller flips
    /// the core process marker only when this is `true`.
    #[must_use]
    pub fn is_unbridled(&self) -> bool {
        matches!(self.source, CaveatsSource::Unbridled { .. })
    }

    /// Pure resolution given the (optional) env value and (optional) home dir.
    /// Factored out so tests drive it without touching real process state.
    ///
    /// # Errors
    /// See [`GrantedCaveats::load`].
    pub fn resolve(env: Option<&str>, home: Option<&Path>) -> anyhow::Result<Self> {
        // 1. Inline JSON grant.
        if let Some(json) = env {
            let caveats: Caveats = serde_json::from_str(json).map_err(|e| {
                anyhow::anyhow!("{ENV_CAVEATS} is set but is not valid Caveats JSON: {e}")
            })?;
            return Ok(Self {
                caveats,
                source: CaveatsSource::Env,
            });
        }

        // 2. Per-host config file.
        if let Some(home) = home {
            let path = home.join(".agent-bridle").join("config.toml");
            if path.is_file() {
                let caveats = load_from_config(&path)?;
                return Ok(Self {
                    caveats,
                    source: CaveatsSource::ConfigFile(path),
                });
            }
        }

        // 3. Default: DENY-ALL (fail-closed). A missing grant grants nothing.
        Ok(Self {
            caveats: deny_all(),
            source: CaveatsSource::FailClosedDefault,
        })
    }

    /// A human-readable, one-line provenance banner for stderr. When the leash
    /// is the unconfined default, the line is a prominent WARNING.
    #[must_use]
    pub fn banner(&self) -> String {
        match &self.source {
            CaveatsSource::Env => {
                format!("agent-bridle-mcp: leash loaded from ${ENV_CAVEATS} (JSON)")
            }
            CaveatsSource::ConfigFile(p) => {
                format!(
                    "agent-bridle-mcp: leash loaded from {} [caveats]",
                    p.display()
                )
            }
            CaveatsSource::FailClosedDefault => format!(
                "agent-bridle-mcp: no grant configured (no ${ENV_CAVEATS}, no \
                 ~/.agent-bridle/config.toml [caveats]) — running DENY-ALL \
                 (fail-closed); every tool is refused. Set ${ENV_CAVEATS} or \
                 [caveats] to grant authority."
            ),
            CaveatsSource::Unbridled { .. } => format!(
                "\n\
                 ============================ !!! UNBRIDLED !!! ============================\n\
                 agent-bridle-mcp: the confinement MECHANISM is OFF (ADR 0018) — tools run\n\
                 NATIVELY, with no OS sandbox. Your configured OCAP grant still gates each\n\
                 call (advisory) and the human step-up gate still applies; every result\n\
                 discloses `unbridled`. Acked via ${ENV_UNBRIDLE_ACK}. Unset ${ENV_MODE}\n\
                 to run confined again.\n\
                 =========================================================================="
            ),
            CaveatsSource::UnbridleRefused { reason } => format!(
                "agent-bridle-mcp: WARNING — {reason}. REFUSING to unbridle; running \
                 DENY-ALL (fail-closed). Set ${ENV_UNBRIDLE_ACK}={UNBRIDLE_ACK_TOKEN} to \
                 unbridle, or unset ${ENV_MODE} to run confined."
            ),
        }
    }
}

/// The shape of `~/.agent-bridle/config.toml` we care about: a `[caveats]`
/// table deserializing straight into [`Caveats`]. Other top-level keys are
/// ignored, so the file can carry unrelated host config too.
#[derive(serde::Deserialize)]
struct Config {
    caveats: Option<Caveats>,
}

/// Read and parse the `[caveats]` table from a config file. A file that exists
/// but has no `[caveats]` table is treated as "no grant configured" → DENY-ALL
/// (fail-closed, §9.3), matching the fall-through semantics of a missing file.
fn load_from_config(path: &Path) -> anyhow::Result<Caveats> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    let cfg: Config = toml::from_str(&text)
        .map_err(|e| anyhow::anyhow!("cannot parse {} [caveats]: {e}", path.display()))?;
    Ok(cfg.caveats.unwrap_or_else(deny_all))
}

/// Resolve `$HOME` without pulling in a dirs crate (lean dep budget).
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridle::{CountBound, Scope};

    #[test]
    fn env_json_is_first_and_parses_the_mesh_shape() {
        // The exact agent-mesh Caveats serde shape: "all" / {"only":[..]} /
        // {"at_most":N}.
        let json = r#"{
            "fs_read": "all",
            "fs_write": "all",
            "exec": { "only": ["echo"] },
            "net": "all",
            "max_calls": { "at_most": 3 },
            "valid_for_generation": "all"
        }"#;
        let g = GrantedCaveats::resolve(Some(json), None).unwrap();
        assert_eq!(g.source, CaveatsSource::Env);
        assert_eq!(g.caveats.exec, Scope::only(["echo".to_string()]));
        assert_eq!(g.caveats.max_calls, CountBound::AtMost(3));
    }

    #[test]
    fn malformed_env_json_is_an_error() {
        let err = GrantedCaveats::resolve(Some("{ not json"), None).unwrap_err();
        assert!(err.to_string().contains(ENV_CAVEATS), "got: {err}");
    }

    #[test]
    fn config_toml_is_second() {
        let dir = tempdir();
        let ab = dir.join(".agent-bridle");
        std::fs::create_dir_all(&ab).unwrap();
        std::fs::write(
            ab.join("config.toml"),
            r#"
[caveats]
fs_read = "all"
fs_write = "all"
exec = { only = ["git", "cargo"] }
net = "all"
max_calls = { at_most = 5 }
valid_for_generation = "all"
"#,
        )
        .unwrap();

        let g = GrantedCaveats::resolve(None, Some(&dir)).unwrap();
        assert!(matches!(g.source, CaveatsSource::ConfigFile(_)));
        assert_eq!(
            g.caveats.exec,
            Scope::only(["git".to_string(), "cargo".to_string()])
        );
        assert_eq!(g.caveats.max_calls, CountBound::AtMost(5));
    }

    #[test]
    fn env_wins_over_config() {
        let dir = tempdir();
        let ab = dir.join(".agent-bridle");
        std::fs::create_dir_all(&ab).unwrap();
        std::fs::write(ab.join("config.toml"), "[caveats]\nexec = { only = [\"git\"] }\nfs_read=\"all\"\nfs_write=\"all\"\nnet=\"all\"\nmax_calls=\"unlimited\"\nvalid_for_generation=\"all\"\n").unwrap();

        let json = r#"{"fs_read":"all","fs_write":"all","exec":{"only":["echo"]},"net":"all","max_calls":"unlimited","valid_for_generation":"all"}"#;
        let g = GrantedCaveats::resolve(Some(json), Some(&dir)).unwrap();
        assert_eq!(g.source, CaveatsSource::Env);
        assert_eq!(g.caveats.exec, Scope::only(["echo".to_string()]));
    }

    #[test]
    fn default_is_fail_closed_deny_all() {
        // §9.3: no grant configured ⇒ DENY-ALL, never top(). A missing grant must
        // grant nothing, and the banner must say so (no "UNCONFINED" footgun).
        let dir = tempdir(); // no config file inside
        let g = GrantedCaveats::resolve(None, Some(&dir)).unwrap();
        assert_eq!(g.source, CaveatsSource::FailClosedDefault);
        assert_eq!(g.caveats, deny_all());
        assert_ne!(g.caveats, Caveats::top(), "default must NOT be unconfined");
        assert_eq!(g.caveats.fs_write, Scope::none());
        assert_eq!(g.caveats.exec, Scope::none());
        assert_eq!(g.caveats.max_calls, CountBound::AtMost(0));
        assert!(g.banner().contains("DENY-ALL"), "banner: {}", g.banner());
        assert!(g.banner().contains("fail-closed"), "banner: {}", g.banner());
    }

    // ── ADR 0018 unbridle (I12) ──────────────────────────────────────────────

    fn base_grant(caveats: Caveats) -> GrantedCaveats {
        GrantedCaveats {
            caveats,
            source: CaveatsSource::Env,
        }
    }

    #[test]
    fn unbridle_two_key_keeps_the_configured_grant() {
        let grant = Caveats {
            exec: Scope::only(["git".to_string()]),
            ..deny_all()
        };
        let g = GrantedCaveats::apply_unbridle(
            base_grant(grant.clone()),
            Some("unbridle"),
            Some("i-understand-this-is-dangerous"),
        );
        assert!(g.is_unbridled());
        assert!(matches!(g.source, CaveatsSource::Unbridled { .. }));
        // The configured grant is KEPT — unbridle never widens authority to top().
        assert_eq!(g.caveats, grant);
        assert_ne!(g.caveats, Caveats::top());
        assert!(g.banner().contains("UNBRIDLED"), "banner: {}", g.banner());
    }

    #[test]
    fn unbridle_without_matching_ack_fails_closed() {
        // Mode set, ack missing/empty/bare/stale ⇒ hard refusal to DENY-ALL.
        for ack in [
            None,
            Some(""),
            Some("1"),
            Some("true"),
            Some("i-understand"),
        ] {
            let g =
                GrantedCaveats::apply_unbridle(base_grant(Caveats::top()), Some("unbridle"), ack);
            assert!(
                matches!(g.source, CaveatsSource::UnbridleRefused { .. }),
                "ack={ack:?} must be refused"
            );
            assert!(!g.is_unbridled());
            assert_eq!(g.caveats, deny_all(), "refused unbridle fails closed");
            assert!(g.banner().contains("REFUSING"), "banner: {}", g.banner());
        }
    }

    #[test]
    fn neither_key_alone_unbridles() {
        let grant = Caveats {
            exec: Scope::only(["git".to_string()]),
            ..deny_all()
        };
        // The ack without the mode does nothing (two-key).
        let g1 = GrantedCaveats::apply_unbridle(
            base_grant(grant.clone()),
            None,
            Some("i-understand-this-is-dangerous"),
        );
        assert_eq!(g1.source, CaveatsSource::Env);
        assert!(!g1.is_unbridled());
        // A non-unbridle mode leaves the resolved grant untouched.
        let g2 = GrantedCaveats::apply_unbridle(
            base_grant(grant),
            Some("bridled"),
            Some("i-understand-this-is-dangerous"),
        );
        assert_eq!(g2.source, CaveatsSource::Env);
    }

    #[test]
    fn config_file_without_caveats_table_is_fail_closed() {
        // An existing config that declares no [caveats] grants nothing, not top().
        let dir = tempdir();
        let ab = dir.join(".agent-bridle");
        std::fs::create_dir_all(&ab).unwrap();
        std::fs::write(ab.join("config.toml"), "# host config, no caveats\n").unwrap();
        let g = GrantedCaveats::resolve(None, Some(&dir)).unwrap();
        assert_eq!(g.caveats, deny_all());
    }

    #[test]
    fn missing_home_falls_through_to_fail_closed_default() {
        let g = GrantedCaveats::resolve(None, None).unwrap();
        assert_eq!(g.source, CaveatsSource::FailClosedDefault);
        assert_eq!(g.caveats, deny_all());
    }

    /// A unique temp dir under the test temp root, no external crate needed.
    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "agent-bridle-mcp-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
}
