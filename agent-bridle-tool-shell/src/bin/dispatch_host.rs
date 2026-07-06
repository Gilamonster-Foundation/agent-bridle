//! Dispatch-capable host binary for the carried-coreutils integration test
//! (issue #206). Its `main` calls [`maybe_dispatch`] first, so the brush engine's
//! carried coreutils shims — which re-exec `<self> --invoke-bundled <name>` —
//! resolve **in-process against THIS binary**. Run it with the environment
//! scrubbed (`env_clear`) to prove carried `ls`/`cat` work with no host tools.
//!
//! Usage: `dispatch_host <cmd> [cwd]` — runs `<cmd>` through the confined brush
//! engine under full-access, prints captured stdout/stderr, exits with the
//! command's code.

use agent_bridle_core::{Caveats, Gate, Tool};
use agent_bridle_tool_shell::{maybe_dispatch, BrushShellTool};

fn main() {
    // MUST be first: if invoked as `<self> --invoke-bundled <name> …`, run the
    // carried coreutil in-process (a fresh post-exec process — safe) and exit.
    if let Some(code) = maybe_dispatch() {
        std::process::exit(code);
    }

    let mut args = std::env::args().skip(1);
    let cmd = args.next().expect("usage: dispatch_host <cmd> [cwd]");
    let cwd = args.next();

    let tool = BrushShellTool::new();
    let ctx = Gate::new(0)
        .authorize(&tool, &Caveats::top())
        .expect("authorize");

    let mut json = serde_json::json!({ "cmd": cmd });
    if let Some(cwd) = cwd {
        json["cwd"] = serde_json::Value::String(cwd);
    }

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let out = rt
        .block_on(async { tool.invoke(json, &ctx).await })
        .expect("invoke");

    if let Some(s) = out.get("stdout").and_then(|v| v.as_str()) {
        print!("{s}");
    }
    if let Some(s) = out.get("stderr").and_then(|v| v.as_str()) {
        eprint!("{s}");
    }
    let code = out
        .get("exit_code")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(1);
    std::process::exit(code as i32);
}
