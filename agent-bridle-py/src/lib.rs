//! `agent_bridle` — the PyO3 wheel for **Pillar A** (DESIGN §8).
//!
//! `pip install agent-bridle`, then call the `Caveats`-confined tool
//! [`Registry`](agent_bridle::Registry) **in-process** from Python:
//!
//! ```python
//! import agent_bridle
//! # NOTE: the `shell` tool exposed by this wheel is currently the fail-closed
//! # STUB — the brush-backed confined shell is pending an upstream brush merge
//! # (see the workspace CHANGELOG). It DENIES every invocation and spawns
//! # nothing, raising `BridleDenied`:
//! try:
//!     agent_bridle.invoke(
//!         "shell",
//!         {"program": "echo", "args": ["hi"]},
//!         {"exec": {"only": ["echo"]}},
//!     )
//! except agent_bridle.BridleDenied as e:
//!     print("shell is a stub:", e)  # mentions --insecure / --dangerously-allow-all
//! ```
//!
//! The `shell` tool's input shape is unchanged for when the confined shell
//! returns: argv form (`program` + `args`) or a free-form `cmd` string.
//!
//! The leash is the same one the Rust hosts use: every dispatch flows through
//! the registry's [`Gate`](agent_bridle::Gate), which mints the tool's
//! `ToolContext` from the *meet* of granted-and-required authority. A leash
//! denial (or any tool error) surfaces in Python as [`BridleDenied`], a
//! subclass of the built-in `PermissionError`.
//!
//! ## Caveats shape (self-contained)
//!
//! `caveats` is an ordinary Python `dict` in the agent-mesh-protocol **Rust**
//! [`Caveats`](agent_mesh_protocol::Caveats) serde shape — you do **not** need
//! to `import agent_mesh`:
//!
//! - string axes `fs_read` / `fs_write` / `exec` / `net`: either `"all"` or
//!   `{"only": ["item", …]}`;
//! - `max_calls`: either `"unlimited"` or `{"at_most": N}`;
//! - `valid_for_generation`: either `"all"` or `{"only": [N, …]}` (`u64`s).
//!
//! Any omitted axis defaults to its **top** (unrestricted). This is exactly the
//! shape `serde_json::to_value(&Caveats)` produces in Rust, so a grant a Rust
//! host already holds round-trips straight through.
//!
//! Interop note: the `agent_mesh.core.Caveats` *pyclass* (agent-mesh PR #18)
//! exposes a friendlier surface — `fs_read=["/repo"]` / `max_calls=10` /
//! `top()`'s axes as `None`. Its `.to_json()` is **not** identical to this Rust
//! serde shape. To pass an agent-mesh pyclass grant here, translate each axis to
//! the serde form above (e.g. `["echo"]` → `{"only": ["echo"]}`, `None` →
//! omit-the-axis, `10` → `{"at_most": 10}`). Both describe the *same* lattice;
//! only the JSON spelling differs.
//!
//! `caveats=None` runs **UNCONFINED** (`Caveats::top()`) and prints a stderr
//! WARNING, because an unconfined leash defeats the purpose of the bridle.

#![forbid(unsafe_code)]

use std::sync::OnceLock;

use agent_bridle::{registry, Caveats, Registry};
use pyo3::exceptions::PyPermissionError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

pyo3::create_exception!(
    agent_bridle,
    BridleDenied,
    PyPermissionError,
    "Raised when the capability leash denies a tool dispatch (or the tool \
     errors). Subclass of `PermissionError`; its message carries the reason."
);

/// The one shared tokio runtime that bridges the registry's async `dispatch`
/// to Python's synchronous call boundary. Built once, lazily, and reused for
/// every [`invoke`] call (DESIGN: one shared runtime via a `OnceCell`).
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build the agent-bridle tokio runtime")
    })
}

/// The process-wide tool registry (the host's compiled feature set: `shell` is
/// on, but as the fail-closed STUB — the brush-backed confined shell is pending
/// upstream, see the workspace CHANGELOG). Built once and reused.
fn shared_registry() -> &'static Registry {
    static REG: OnceLock<Registry> = OnceLock::new();
    REG.get_or_init(registry)
}

/// Dispatch `tool` with `args` through the registry's leash.
///
/// `caveats` is the granted authority as a dict in the agent-mesh `Caveats`
/// serde shape (see the module docs). `None` → unconfined `Caveats::top()` with
/// a stderr WARNING.
///
/// Returns the tool's result as a Python `dict`. A leash denial (out-of-scope
/// `exec`/`fs`/`net`, exhausted `max_calls`, wrong generation) or any tool
/// error raises [`BridleDenied`] (a `PermissionError`) carrying the reason.
#[pyfunction]
#[pyo3(signature = (tool, args, caveats=None))]
fn invoke<'py>(
    py: Python<'py>,
    tool: &str,
    args: &Bound<'py, PyDict>,
    caveats: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    // 1. Args: a Python dict → serde_json::Value (an object).
    let args_json = py_dict_to_json(args)?;

    // 2. Caveats: dict → Caveats, or top() (UNCONFINED, with a warning).
    let granted = match caveats {
        Some(c) => caveats_from_py(c)?,
        None => {
            eprintln!(
                "WARNING: agent_bridle.invoke(\"{tool}\", …) was called with \
                 caveats=None — running UNCONFINED (Caveats::top()), with FULL \
                 ambient authority. Pass a caveats dict to confine it."
            );
            Caveats::top()
        }
    };

    // 3. Dispatch through the leash, bridging async → sync on the shared
    //    runtime. `detach` releases the GIL for the (possibly blocking) tool
    //    work so other Python threads can run (pyo3 0.28 renamed the old
    //    `allow_threads` to `detach`).
    let result =
        py.detach(|| runtime().block_on(shared_registry().dispatch(tool, args_json, &granted)));

    match result {
        Ok(value) => {
            // A dispatch can return Ok yet carry a STRUCTURED in-band denial:
            // a free-form shell `cmd` the interceptor refused returns
            // `denied: true` in the envelope (the brush run exited non-zero, but
            // a capability was refused). Raise BridleDenied for that too — so
            // free-form denials are covered, not only the argv/Err-path ones —
            // reading the structured field, NOT string-matching stderr.
            if let Some(reason) = structured_denial_reason(&value) {
                return Err(BridleDenied::new_err::<String>(reason));
            }
            // The tool envelope is always a JSON object → a Python dict.
            json_to_py(py, &value)?.cast_into::<PyDict>().map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                    "tool returned a non-object result; expected a JSON object",
                )
            })
        }
        // Every ToolError (Denied, NotFound, Budget, Generation, Exec, Other)
        // surfaces as BridleDenied carrying the human-readable reason. The
        // leash outcomes (Denied/Budget/Generation) are the load-bearing ones.
        Err(e) => Err(BridleDenied::new_err::<String>(e.to_string())),
    }
}

/// If a tool result carries the structured `denied: true` flag, build the
/// human-readable reason from its `denials` list. Returns `None` when the
/// result was not denied (the normal path).
fn structured_denial_reason(value: &serde_json::Value) -> Option<String> {
    if value.get("denied").and_then(serde_json::Value::as_bool) != Some(true) {
        return None;
    }
    let reasons: Vec<String> = value
        .get("denials")
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|d| d.get("reason").and_then(serde_json::Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Some(if reasons.is_empty() {
        "denied: the capability leash refused an operation".to_string()
    } else {
        reasons.join("; ")
    })
}

/// The names of the registered tools (sorted).
#[pyfunction]
fn tool_names() -> Vec<String> {
    shared_registry()
        .tool_names()
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// The MCP `tools/list` schemas: one dict per tool (`name` + `inputSchema`).
#[pyfunction]
fn tool_definitions(py: Python<'_>) -> PyResult<Vec<Py<PyDict>>> {
    shared_registry()
        .tool_definitions()
        .iter()
        .map(|def| {
            json_to_py(py, def)?
                .cast_into::<PyDict>()
                .map(Bound::unbind)
                .map_err(|_| {
                    PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                        "tool definition was not a JSON object",
                    )
                })
        })
        .collect()
}

/// Parse a Python caveats dict (agent-mesh `Caveats` serde shape) into a Rust
/// [`Caveats`]. Omitted axes default to their top.
///
/// We round-trip through `serde_json::Value` (the dict → JSON), then build the
/// `Caveats` axis-by-axis so a *partial* dict is accepted (serde's derive would
/// reject one missing a field). This keeps the wheel self-contained: no
/// `agent_mesh` import needed, while the shape matches it exactly.
fn caveats_from_py(dict: &Bound<'_, PyDict>) -> PyResult<Caveats> {
    use agent_mesh_protocol::{CountBound, Scope};

    let obj = py_dict_to_json(dict)?;
    let map = obj.as_object().expect("py_dict_to_json yields an object");

    // A field-name typo would silently be ignored otherwise; surface it.
    const FIELDS: [&str; 6] = [
        "fs_read",
        "fs_write",
        "exec",
        "net",
        "max_calls",
        "valid_for_generation",
    ];
    for key in map.keys() {
        if !FIELDS.contains(&key.as_str()) {
            return Err(invalid_caveats(format!(
                "unknown caveats field {key:?}; expected one of {FIELDS:?}"
            )));
        }
    }

    let str_axis = |name: &str| -> PyResult<Scope<String>> {
        match map.get(name) {
            None => Ok(Scope::top()),
            Some(v) => parse_str_scope(name, v),
        }
    };

    let gen_axis = |name: &str| -> PyResult<Scope<u64>> {
        match map.get(name) {
            None => Ok(Scope::top()),
            Some(v) => parse_u64_scope(name, v),
        }
    };

    let max_calls = match map.get("max_calls") {
        None => CountBound::top(),
        Some(v) => parse_count_bound(v)?,
    };

    Ok(Caveats {
        fs_read: str_axis("fs_read")?,
        fs_write: str_axis("fs_write")?,
        exec: str_axis("exec")?,
        net: str_axis("net")?,
        max_calls,
        valid_for_generation: gen_axis("valid_for_generation")?,
    })
}

/// Parse one string axis: `"all"` or `{"only": ["item", …]}`.
fn parse_str_scope(
    name: &str,
    v: &serde_json::Value,
) -> PyResult<agent_mesh_protocol::Scope<String>> {
    use agent_mesh_protocol::Scope;
    match v {
        serde_json::Value::String(s) if s == "all" => Ok(Scope::All),
        serde_json::Value::Object(o) => {
            let items = o.get("only").and_then(|x| x.as_array()).ok_or_else(|| {
                invalid_caveats(format!("{name}: object form must be {{\"only\": [..]}}"))
            })?;
            let mut set = std::collections::BTreeSet::new();
            for item in items {
                let s = item
                    .as_str()
                    .ok_or_else(|| invalid_caveats(format!("{name}.only items must be strings")))?;
                set.insert(s.to_string());
            }
            Ok(Scope::Only(set))
        }
        _ => Err(invalid_caveats(format!(
            "{name} must be \"all\" or {{\"only\": [..]}}"
        ))),
    }
}

/// Parse the `valid_for_generation` axis: `"all"` or `{"only": [N, …]}` (u64s).
fn parse_u64_scope(name: &str, v: &serde_json::Value) -> PyResult<agent_mesh_protocol::Scope<u64>> {
    use agent_mesh_protocol::Scope;
    match v {
        serde_json::Value::String(s) if s == "all" => Ok(Scope::All),
        serde_json::Value::Object(o) => {
            let items = o.get("only").and_then(|x| x.as_array()).ok_or_else(|| {
                invalid_caveats(format!("{name}: object form must be {{\"only\": [..]}}"))
            })?;
            let mut set = std::collections::BTreeSet::new();
            for item in items {
                let n = item.as_u64().ok_or_else(|| {
                    invalid_caveats(format!("{name}.only items must be non-negative integers"))
                })?;
                set.insert(n);
            }
            Ok(Scope::Only(set))
        }
        _ => Err(invalid_caveats(format!(
            "{name} must be \"all\" or {{\"only\": [..]}}"
        ))),
    }
}

/// Parse `max_calls`: `"unlimited"` or `{"at_most": N}`.
fn parse_count_bound(v: &serde_json::Value) -> PyResult<agent_mesh_protocol::CountBound> {
    use agent_mesh_protocol::CountBound;
    match v {
        serde_json::Value::String(s) if s == "unlimited" => Ok(CountBound::Unlimited),
        serde_json::Value::Object(o) => {
            let n = o
                .get("at_most")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    invalid_caveats("max_calls object form must be {\"at_most\": N}".to_string())
                })?;
            Ok(CountBound::AtMost(n))
        }
        _ => Err(invalid_caveats(
            "max_calls must be \"unlimited\" or {\"at_most\": N}".to_string(),
        )),
    }
}

/// A `ValueError` for a malformed caveats dict (distinct from a leash denial:
/// the grant itself is bad input, not an authority refusal).
fn invalid_caveats(msg: String) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid caveats: {msg}"))
}

// ── JSON ⇄ Python conversion (self-contained; no pythonize dep) ──────────────

/// Convert a Python `dict` to a `serde_json::Value::Object`.
fn py_dict_to_json(dict: &Bound<'_, PyDict>) -> PyResult<serde_json::Value> {
    py_any_to_json(dict.as_any())
}

/// Convert an arbitrary Python value to a `serde_json::Value`.
fn py_any_to_json(obj: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    use serde_json::Value;

    if obj.is_none() {
        return Ok(Value::Null);
    }
    // bool must be checked before int (Python bool is a subclass of int).
    if let Ok(b) = obj.extract::<bool>() {
        return Ok(Value::Bool(b));
    }
    if let Ok(i) = obj.extract::<i64>() {
        return Ok(Value::from(i));
    }
    if let Ok(u) = obj.extract::<u64>() {
        return Ok(Value::from(u));
    }
    if let Ok(f) = obj.extract::<f64>() {
        return Ok(serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null));
    }
    if let Ok(s) = obj.extract::<String>() {
        return Ok(Value::String(s));
    }
    if let Ok(dict) = obj.cast::<PyDict>() {
        let mut map = serde_json::Map::with_capacity(dict.len());
        for (k, v) in dict.iter() {
            let key = k.extract::<String>().map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyTypeError, _>("dict keys must be strings")
            })?;
            map.insert(key, py_any_to_json(&v)?);
        }
        return Ok(Value::Object(map));
    }
    if let Ok(list) = obj.cast::<PyList>() {
        let mut arr = Vec::with_capacity(list.len());
        for item in list.iter() {
            arr.push(py_any_to_json(&item)?);
        }
        return Ok(Value::Array(arr));
    }
    // Tuples and other sequences: best-effort via iteration.
    if let Ok(seq) = obj.try_iter() {
        let mut arr = Vec::new();
        for item in seq {
            arr.push(py_any_to_json(&item?)?);
        }
        return Ok(Value::Array(arr));
    }

    Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(format!(
        "cannot convert Python value of type {} to JSON",
        obj.get_type().name()?
    )))
}

/// Convert a `serde_json::Value` to a Python object.
fn json_to_py<'py>(py: Python<'py>, value: &serde_json::Value) -> PyResult<Bound<'py, PyAny>> {
    use serde_json::Value;
    match value {
        Value::Null => Ok(py.None().into_bound(py)),
        Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any())
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_pyobject(py)?.into_any())
            } else {
                let f = n.as_f64().expect("JSON number is i64, u64, or f64");
                Ok(f.into_pyobject(py)?.into_any())
            }
        }
        Value::String(s) => Ok(s.into_pyobject(py)?.into_any()),
        Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(json_to_py(py, item)?)?;
            }
            Ok(list.into_any())
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, json_to_py(py, v)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

/// The `agent_bridle` extension module.
///
/// The Python module name is set explicitly to `agent_bridle` (matching
/// `[lib] name` in Cargo.toml) while the Rust function is named differently:
/// `#[pymodule]` generates a hidden inner module named after the function, so a
/// function literally named `agent_bridle` would shadow the `agent_bridle`
/// *facade crate* and break `use agent_bridle::…`. The `name` attribute keeps
/// the Python-visible name (and the `PyInit_agent_bridle` symbol) correct.
#[pymodule]
#[pyo3(name = "agent_bridle")]
fn agent_bridle_module(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("BridleDenied", py.get_type::<BridleDenied>())?;
    m.add_function(wrap_pyfunction!(invoke, m)?)?;
    m.add_function(wrap_pyfunction!(tool_names, m)?)?;
    m.add_function(wrap_pyfunction!(tool_definitions, m)?)?;
    m.add(
        "__doc__",
        "agent-bridle Pillar A: call the Caveats-confined tool registry in-process.",
    )?;
    Ok(())
}
