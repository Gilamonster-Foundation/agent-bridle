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
//! 3. **Default `Caveats::top()`** — UNCONFINED. Emits a prominent stderr
//!    warning, because an unconfined leash defeats the purpose of the bridle.
//!
//! The TOML/JSON shapes are identical to the Rust `Caveats` serde derive:
//! string axes are either `"all"` or `{ "only": [..] }`; `max_calls` is either
//! `"unlimited"` or `{ "at_most": N }`. See the crate README for full examples.

use std::path::{Path, PathBuf};

use agent_bridle::Caveats;

/// Environment variable carrying an inline JSON grant.
const ENV_CAVEATS: &str = "AGENT_BRIDLE_CAVEATS";

/// Where the granted leash came from — surfaced in the startup banner so an
/// operator can see, at a glance, whether the server is confined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaveatsSource {
    /// Loaded from the `AGENT_BRIDLE_CAVEATS` environment variable (JSON).
    Env,
    /// Loaded from `~/.agent-bridle/config.toml` `[caveats]`.
    ConfigFile(PathBuf),
    /// No grant configured — defaulted to `Caveats::top()` (UNCONFINED).
    UnconfinedDefault,
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
        Self::resolve(env.as_deref(), home.as_deref())
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

        // 3. Default: UNCONFINED.
        Ok(Self {
            caveats: Caveats::top(),
            source: CaveatsSource::UnconfinedDefault,
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
            CaveatsSource::UnconfinedDefault => format!(
                "WARNING: agent-bridle-mcp is running UNCONFINED \
                 (no ${ENV_CAVEATS}, no ~/.agent-bridle/config.toml [caveats]); \
                 every tool runs with FULL ambient authority. Set ${ENV_CAVEATS} \
                 or [caveats] to confine it."
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
/// but has no `[caveats]` table is treated as "no grant configured" → top, to
/// keep the same fall-through semantics as a missing file.
fn load_from_config(path: &Path) -> anyhow::Result<Caveats> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    let cfg: Config = toml::from_str(&text)
        .map_err(|e| anyhow::anyhow!("cannot parse {} [caveats]: {e}", path.display()))?;
    Ok(cfg.caveats.unwrap_or_else(Caveats::top))
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
    fn default_is_unconfined_top_with_warning_banner() {
        let dir = tempdir(); // no config file inside
        let g = GrantedCaveats::resolve(None, Some(&dir)).unwrap();
        assert_eq!(g.source, CaveatsSource::UnconfinedDefault);
        assert_eq!(g.caveats, Caveats::top());
        assert!(g.banner().contains("UNCONFINED"), "banner: {}", g.banner());
        assert!(g.banner().starts_with("WARNING"));
    }

    #[test]
    fn missing_home_falls_through_to_default() {
        let g = GrantedCaveats::resolve(None, None).unwrap();
        assert_eq!(g.source, CaveatsSource::UnconfinedDefault);
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
