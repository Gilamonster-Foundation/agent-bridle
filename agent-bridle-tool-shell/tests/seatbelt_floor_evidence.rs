//! macOS Seatbelt **CONFINED-floor** real-resource evidence (agent-bridle#317 /
//! newt-agent#1632). This is the floor the content-addressed provenance chain
//! MEASURES (board: `2026-08-09_content-addressed-authority-provenance-CONTRACT`,
//! object `EnforcementEvidence.observed: EnforcementReport`): for a Newt-shaped
//! grant it witnesses each restricted floor axis's ACTUAL per-axis strength on
//! real `sandbox-exec`, not merely that a sandbox engaged.
//!
//! The Newt `CONFINED` contract is `{fs_read Kernel, fs_write Kernel, net Kernel,
//! exec Interceptor}`. Here a grant whose exec names a NON-launcher program
//! (`touch`) witnesses `exec = Kernel` too (exact identity closure, model B), and
//! the fs/net axes are Kernel — so the measured report meets the floor on every
//! restricted axis, with `sandbox_kind == seatbelt` pinned and a real out-of-fence
//! denial proving the fence is not vacuous. A missing backend self-skips (the
//! `unconfined-fallback-on-missing-backend` truth is carried by the fail-closed
//! `command_prefix`; `/usr/bin/sandbox-exec` is SIP-present on any real host).
#![cfg(all(target_os = "macos", feature = "macos-seatbelt", feature = "shell"))]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use agent_bridle_core::{seatbelt_is_supported, Caveats, Gate, Scope, Tool, ToolContext};
use agent_bridle_tool_shell::ShellTool;

fn ctx(granted: Caveats) -> ToolContext {
    Gate::new(0)
        .authorize(&ShellTool::new(), &granted)
        .expect("authorize")
}

fn unique_temp(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "ab-floor-{}-{}-{}",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

/// The measured per-axis witnesses for a CONFINED-shaped grant meet the floor on
/// every restricted axis (`fs_read`/`fs_write`/`net`/`exec` = `kernel`), under a
/// real Seatbelt sandbox — the truthful `EnforcementReport` the provenance
/// `EnforcementEvidence` binds. A real out-of-fence write is kernel-DENIED, so the
/// witnesses are not vacuous.
#[tokio::test]
async fn real_seatbelt_confined_floor_axes_are_witnessed_kernel() {
    if !seatbelt_is_supported() {
        eprintln!("skipping: /usr/bin/sandbox-exec unavailable");
        return;
    }
    let ws = unique_temp("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let outside = unique_temp("outside");
    std::fs::create_dir_all(&outside).unwrap();

    // A Newt-shaped grant. `touch` is a NON-launcher program, so its Seatbelt
    // process-exec* closure is exact (Kernel), unlike a `sh` grant (Interceptor,
    // model B). fs_read/fs_write are scoped to the workspace; net is deny-all.
    let ws_s = ws.to_string_lossy().into_owned();
    let confined = Caveats {
        fs_read: Scope::only([ws_s.clone()]),
        fs_write: Scope::only([ws_s.clone()]),
        net: Scope::none(),
        exec: Scope::only(["touch".to_string()]),
        ..Caveats::top()
    };

    // In-fence write succeeds AND every restricted floor axis is witnessed Kernel.
    let inside = ShellTool::new()
        .invoke(
            serde_json::json!({ "cmd": format!("touch {ws_s}/ok") }),
            &ctx(confined.clone()),
        )
        .await
        .expect("invoke");
    assert_eq!(inside["sandbox_kind"], "seatbelt", "{inside}");
    assert_eq!(
        inside["exit_code"], 0,
        "in-fence write must succeed: {inside}"
    );
    let e = &inside["enforcement"];
    for axis in ["fs_read", "fs_write", "net", "exec"] {
        assert_eq!(
            e[axis], "kernel",
            "measured floor witness for {axis} must be kernel (the CONFINED floor): {inside}"
        );
    }
    assert!(ws.join("ok").exists(), "the in-scope file must exist");

    // Real out-of-fence write is kernel-DENIED — the fs witnesses are not vacuous.
    let escape = ShellTool::new()
        .invoke(
            serde_json::json!({ "cmd": format!("touch {}/escape", outside.to_string_lossy()) }),
            &ctx(confined),
        )
        .await
        .expect("invoke");
    assert_eq!(escape["sandbox_kind"], "seatbelt", "{escape}");
    assert_ne!(
        escape["exit_code"], 0,
        "a write outside fs_write must be kernel-denied: {escape}"
    );
    assert!(
        !outside.join("escape").exists(),
        "the out-of-fence file must NOT have been created"
    );

    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(&outside);
}

/// Scope-fidelity at the floor (the #317 review, witnessed): a grant whose exec
/// names `sh` measures `exec = interceptor`, NOT `kernel` — Apple's `/bin/sh`
/// pulls `/bin/bash` into the process-exec* closure, so the fence permits a
/// program the Caveat did not name. The provenance `EnforcementEvidence` for such
/// a grant must record `interceptor` (a truthful degradation), never an
/// over-claimed Kernel. fs/net stay Kernel.
#[tokio::test]
async fn real_seatbelt_exec_floor_downgrades_to_interceptor_for_sh() {
    if !seatbelt_is_supported() {
        return;
    }
    let ws = unique_temp("ws-sh");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let grant = Caveats {
        fs_write: Scope::only([ws_s.clone()]),
        net: Scope::none(),
        exec: Scope::only(["sh".to_string()]),
        ..Caveats::top()
    };
    let out = ShellTool::new()
        .invoke(
            serde_json::json!({ "cmd": format!("touch {ws_s}/ok") }),
            &ctx(grant),
        )
        .await
        .expect("invoke");
    assert_eq!(out["sandbox_kind"], "seatbelt", "{out}");
    assert_eq!(
        out["enforcement"]["exec"], "interceptor",
        "a granted sh widens the closure (/bin/bash) → exec witnessed interceptor, not kernel: {out}"
    );
    assert_eq!(out["enforcement"]["fs_write"], "kernel", "{out}");
    assert_eq!(out["enforcement"]["net"], "kernel", "{out}");
    let _ = std::fs::remove_dir_all(&ws);
}
