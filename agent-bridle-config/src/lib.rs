//! Layered configuration loader for the bridle (agent-bridle#142 / ADR 0017).
//!
//! Resolves a [`BridleConfig`] from four layers, lowest precedence first:
//! **built-in defaults → config file → environment → programmatic API**. Each
//! layer is a *partial* overlay; layers are deep-merged **per field**, so setting
//! one key (e.g. `BRIDLE_LIMITS_MAX_TIMEOUT_SECS=120`) overrides only that field
//! and leaves its siblings at the lower layer's value.
//!
//! The config TYPES live in `agent-bridle-core` (serde-only); this crate is the
//! only place `toml`/env I/O lives, keeping core lean (ADR 0008/0017). It tunes
//! **mechanism** only — the `Caveats` grant (authority) is sourced separately
//! (`agent-bridle-mcp`'s caveats source), and its deny-all default is untouched.
//!
//! [`resolve`] is a **pure function** of `(file, env, api)` — unit-testable with
//! in-memory inputs, no process state. [`load`] is the thin process-facing wrapper.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::path::Path;

use agent_bridle_core::BridleConfig;
use anyhow::{Context, Result};
use serde_json::{Map, Value};

/// Where each layer's value came from, for the startup banner / provenance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigProvenance {
    /// A config file supplied a `[bridle]` table.
    pub file: bool,
    /// One or more `BRIDLE_*` / `AGENT_BRIDLE_CONFIG` env vars applied.
    pub env: bool,
    /// A programmatic overlay was applied.
    pub api: bool,
}

/// Deep-merge `overlay` onto `base` in place: objects merge key-by-key
/// (recursively); any non-object value (scalar, array, null) **replaces** the base
/// value. This gives per-field precedence for the layered resolution.
fn deep_merge(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(slot) => deep_merge(slot, v),
                    None => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (b, o) => *b = o,
    }
}

/// Parse the `[bridle]` table out of a config-file's TOML text into a JSON overlay.
/// Returns `Value::Null` when the file has no `[bridle]` table (its `[caveats]`
/// table and any other content are ignored here — the grant is sourced elsewhere).
fn file_overlay(toml_text: &str) -> Result<Value> {
    let parsed: toml::Value = toml::from_str(toml_text).context("parsing config TOML")?;
    let json: Value = serde_json::to_value(parsed).context("TOML → JSON")?;
    Ok(json.get("bridle").cloned().unwrap_or(Value::Null))
}

/// Coerce an env-var string into the most specific JSON scalar/array: `true`/`false`
/// → bool, all-digits → integer, comma-separated → array (recursively coerced),
/// else string. (Typed deserialization into `BridleConfig` still validates it.)
fn coerce(raw: &str) -> Value {
    if raw.eq_ignore_ascii_case("true") {
        return Value::Bool(true);
    }
    if raw.eq_ignore_ascii_case("false") {
        return Value::Bool(false);
    }
    if let Ok(n) = raw.parse::<u64>() {
        return Value::from(n);
    }
    if raw.contains(',') {
        return Value::Array(raw.split(',').map(|s| coerce(s.trim())).collect());
    }
    Value::String(raw.to_string())
}

/// The known top-level policy areas (the sub-tables of `BridleConfig`). An env var
/// `BRIDLE_<AREA>_<FIELD>` maps to `{ area: { field: value } }`.
const AREAS: &[&str] = &[
    "gate",
    "sandbox",
    "normalization",
    "rootfs",
    "net",
    "limits",
    "web",
    "vm",
];

/// Build a JSON overlay from an env map: the `AGENT_BRIDLE_CONFIG` JSON blob (a full
/// overlay), the legacy aliases, then the generic `BRIDLE_<AREA>_<FIELD>` scalars
/// (later sources override earlier via deep-merge).
fn env_overlay(env: &BTreeMap<String, String>) -> Result<Value> {
    let mut overlay = Value::Object(Map::new());

    // 1. Full-overlay escape hatch (lowest of the env sources).
    if let Some(blob) = env.get("AGENT_BRIDLE_CONFIG") {
        let v: Value = serde_json::from_str(blob).context("AGENT_BRIDLE_CONFIG must be JSON")?;
        deep_merge(&mut overlay, v);
    }

    // 2. Legacy aliases (kept for one release), mapped into the new shape.
    if env
        .get("BRIDLE_REQUIRE_LANDLOCK")
        .is_some_and(|v| truthy(v))
    {
        deep_merge(
            &mut overlay,
            json_at(
                &["sandbox", "backends", "require_landlock"],
                Value::Bool(true),
            ),
        );
    }
    if env
        .get("BRIDLE_REQUIRE_SEATBELT")
        .is_some_and(|v| truthy(v))
    {
        deep_merge(
            &mut overlay,
            json_at(
                &["sandbox", "backends", "require_seatbelt"],
                Value::Bool(true),
            ),
        );
    }
    if let Some(p) = env.get("BRIDLE_NET_AUDIT") {
        deep_merge(
            &mut overlay,
            json_at(&["limits", "audit_sink"], Value::String(p.clone())),
        );
    }
    if let Some(p) = env.get("BRIDLE_JAILD_SOCKET") {
        deep_merge(
            &mut overlay,
            json_at(&["vm", "jaild_socket"], Value::String(p.clone())),
        );
    }
    if let Some(p) = env.get("BRIDLE_JAIL_INIT") {
        deep_merge(
            &mut overlay,
            json_at(&["vm", "jail_init"], Value::String(p.clone())),
        );
    }

    // 3. Generic BRIDLE_<AREA>_<FIELD> (and BRIDLE_MODE) — highest of the env sources.
    for (k, raw) in env {
        let Some(rest) = k.strip_prefix("BRIDLE_") else {
            continue;
        };
        let lower = rest.to_ascii_lowercase();
        if lower == "mode" {
            deep_merge(
                &mut overlay,
                json_at(&["mode"], Value::String(raw.to_ascii_lowercase())),
            );
            continue;
        }
        // area is the first segment; field is the remainder.
        let Some((area, field)) = lower.split_once('_') else {
            continue;
        };
        if AREAS.contains(&area) && !field.is_empty() {
            deep_merge(&mut overlay, json_at(&[area, field], coerce(raw)));
        }
    }

    Ok(overlay)
}

/// `true` if the env value is a set/enabled flag (`1`/`true`/`yes`).
fn truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}

/// Build `{ path0: { path1: { … : val } } }`.
fn json_at(path: &[&str], val: Value) -> Value {
    let mut v = val;
    for key in path.iter().rev() {
        let mut m = Map::new();
        m.insert((*key).to_string(), v);
        v = Value::Object(m);
    }
    v
}

/// Resolve a [`BridleConfig`] from the three overlay layers atop the defaults.
/// Pure: no file/env I/O. `file_toml` is a config file's full TOML text (its
/// `[bridle]` table is used); `env` is the relevant env vars; `api` is a
/// programmatic overlay (already JSON). Returns the config + its provenance.
pub fn resolve(
    file_toml: Option<&str>,
    env: &BTreeMap<String, String>,
    api: Option<Value>,
) -> Result<(BridleConfig, ConfigProvenance)> {
    let mut prov = ConfigProvenance::default();
    let mut merged = serde_json::to_value(BridleConfig::default()).expect("config is serializable");

    if let Some(text) = file_toml {
        let fo = file_overlay(text)?;
        if !fo.is_null() {
            prov.file = true;
            deep_merge(&mut merged, fo);
        }
    }

    let eo = env_overlay(env)?;
    if eo.as_object().is_some_and(|m| !m.is_empty()) {
        prov.env = true;
        deep_merge(&mut merged, eo);
    }

    if let Some(a) = api {
        if !a.is_null() {
            prov.api = true;
            deep_merge(&mut merged, a);
        }
    }

    let cfg: BridleConfig =
        serde_json::from_value(merged).context("merged config failed to deserialize")?;
    Ok((cfg, prov))
}

/// Load the process configuration: `~/.agent-bridle/config.toml` (if present) +
/// the process environment, no API overlay. Missing file ⇒ defaults + env only.
pub fn load() -> Result<(BridleConfig, ConfigProvenance)> {
    let file_text = home_config_path().and_then(|p| std::fs::read_to_string(p).ok());
    let env: BTreeMap<String, String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("BRIDLE_") || k == "AGENT_BRIDLE_CONFIG")
        .collect();
    resolve(file_text.as_deref(), &env, None)
}

/// `~/.agent-bridle/config.toml` (the same file the caveats grant reads).
fn home_config_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let p = Path::new(&home).join(".agent-bridle").join("config.toml");
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn no_layers_yields_defaults() {
        let (cfg, prov) = resolve(None, &env(&[]), None).unwrap();
        assert_eq!(cfg, BridleConfig::default());
        assert_eq!(prov, ConfigProvenance::default());
    }

    #[test]
    fn env_overrides_a_single_field_without_clobbering_siblings() {
        let (cfg, prov) = resolve(
            None,
            &env(&[("BRIDLE_LIMITS_MAX_TIMEOUT_SECS", "120")]),
            None,
        )
        .unwrap();
        assert_eq!(cfg.limits.max_timeout_secs, 120);
        // sibling untouched (still the default)
        assert_eq!(
            cfg.limits.default_timeout_secs,
            BridleConfig::default().limits.default_timeout_secs
        );
        assert!(prov.env && !prov.file && !prov.api);
    }

    #[test]
    fn precedence_is_defaults_then_file_then_env_then_api() {
        let file = r#"
            [caveats]
            exec = { only = ["git"] }
            [bridle.limits]
            max_timeout_secs = 100
            default_timeout_secs = 50
        "#;
        // file sets 100/50; env overrides max to 200; api overrides max to 300.
        let (cfg, prov) = resolve(
            Some(file),
            &env(&[("BRIDLE_LIMITS_MAX_TIMEOUT_SECS", "200")]),
            Some(json_at(
                &["limits", "max_timeout_secs"],
                Value::from(300u64),
            )),
        )
        .unwrap();
        assert_eq!(cfg.limits.max_timeout_secs, 300, "api wins");
        assert_eq!(cfg.limits.default_timeout_secs, 50, "file value survives");
        assert!(prov.file && prov.env && prov.api);
    }

    #[test]
    fn bare_file_without_bridle_table_is_defaults() {
        let file = "[caveats]\nexec = { only = [\"git\"] }\n";
        let (cfg, prov) = resolve(Some(file), &env(&[]), None).unwrap();
        assert_eq!(cfg, BridleConfig::default());
        assert!(!prov.file, "no [bridle] table ⇒ file layer inert");
    }

    #[test]
    fn legacy_aliases_map_into_the_new_shape() {
        let (cfg, _) = resolve(
            None,
            &env(&[
                ("BRIDLE_REQUIRE_LANDLOCK", "1"),
                ("BRIDLE_NET_AUDIT", "/tmp/egress.jsonl"),
                ("BRIDLE_JAILD_SOCKET", "/run/x.sock"),
            ]),
            None,
        )
        .unwrap();
        assert!(cfg.sandbox.backends.require_landlock);
        assert_eq!(cfg.limits.audit_sink.as_deref(), Some("/tmp/egress.jsonl"));
        assert_eq!(cfg.vm.jaild_socket.as_deref(), Some("/run/x.sock"));
    }

    #[test]
    fn agent_bridle_config_json_blob_applies_as_an_overlay() {
        let blob = r#"{"limits":{"max_output_bytes":2048},"mode":"unbridle"}"#;
        let (cfg, prov) = resolve(None, &env(&[("AGENT_BRIDLE_CONFIG", blob)]), None).unwrap();
        assert_eq!(cfg.limits.max_output_bytes, 2048);
        assert_eq!(cfg.mode, agent_bridle_core::BridleMode::Unbridle);
        assert!(prov.env);
    }

    #[test]
    fn list_valued_env_extends_via_comma() {
        // sandbox.base_read_paths is a PathList: setting `.extra` via a comma list.
        let (cfg, _) = resolve(
            None,
            &env(&[]),
            Some(json_at(
                &["sandbox", "base_read_paths", "extra"],
                coerce("/opt/a,/opt/b"),
            )),
        )
        .unwrap();
        let resolved = cfg.sandbox.base_read_paths.resolve();
        assert!(resolved.contains(&"/opt/a".to_string()));
        assert!(resolved.contains(&"/opt/b".to_string()));
        // The platform-specific base is preserved (extend, not replace). The
        // default base differs by active backend (Landlock vs Seatbelt; I5-B #144).
        #[cfg(target_os = "macos")]
        let base_entry = "/System";
        #[cfg(not(target_os = "macos"))]
        let base_entry = "/lib";
        assert!(
            resolved.contains(&base_entry.to_string()),
            "base preserved (extend)"
        );
    }
}
