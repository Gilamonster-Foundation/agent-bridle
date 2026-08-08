//! Real-resource proof that the **`ShellTool` production path** installs the
//! `ChildNetworkPolicy::DenyDirect` seccomp egress floor on the child it spawns
//! — closing the UDP/DNS/raw/packet leg Landlock's TCP-only net rule misses —
//! and that the floor is inherited by a forked/exec'd descendant.
//!
//! This grounds the direct-thread `apply` proofs in `agent-bridle-core`
//! (`sandbox::landlock_kernel_tests::deny_direct_*`) against the real tool: it
//! proves the `SandboxPolicy.child_network` field is actually threaded from
//! `ShellTool::with_sandbox_policy` through `run_confined` → `Sandbox::apply` on
//! the same thread that spawns the child.
//!
//! Linux + `linux-landlock`, gated on kernel Landlock + a `python3` probe (the
//! child that attempts an AF_INET socket). Where either is absent the test skips.
#![cfg(all(target_os = "linux", feature = "linux-landlock"))]

use agent_bridle_core::{
    landlock_is_supported, Caveats, ChildNetworkPolicy, Gate, SandboxPolicy, Scope, Tool,
    ToolContext,
};
use agent_bridle_tool_shell::ShellTool;

/// A `ShellTool` carrying the requested child-network policy.
fn tool(child_network: ChildNetworkPolicy) -> ShellTool {
    ShellTool::new().with_sandbox_policy(SandboxPolicy {
        child_network,
        ..SandboxPolicy::default()
    })
}

/// Mint a context for `tool` granting exec of `execs` and denying ALL network
/// (`net: none`, which is what arms `DenyDirect`).
fn ctx(tool: &ShellTool, execs: &[&str]) -> ToolContext {
    let granted = Caveats {
        exec: Scope::only(execs.iter().map(|s| (*s).to_string())),
        net: Scope::none(),
        ..Caveats::top()
    };
    Gate::new(0).authorize(tool, &granted).expect("authorize")
}

fn skip() -> bool {
    if !landlock_is_supported() {
        eprintln!("skipping: kernel lacks Landlock");
        return true;
    }
    if !std::path::Path::new("/usr/bin/python3").exists() {
        eprintln!("skipping: /usr/bin/python3 (the AF_INET probe) not present");
        return true;
    }
    false
}

/// The child CREATES an AF_INET datagram socket. Under DenyDirect the seccomp
/// filter EACCES-denies `socket()` → Python raises `PermissionError` → exit 1;
/// under LandlockOnly the socket is created (Landlock can't filter UDP) → exit 0.
const PROBE: &str =
    r#"python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)""#;

/// A forked/exec'd descendant probe: the child python re-execs python to attempt
/// the socket in a grandchild, and propagates its exit code — so a non-zero
/// result proves the seccomp floor was inherited across the fork/exec.
const DESCENDANT_PROBE: &str = r#"python3 -c "import subprocess,sys; sys.exit(subprocess.run([sys.executable,'-c','import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)']).returncode)""#;

#[tokio::test]
async fn shell_tool_deny_direct_denies_a_childs_udp_socket() {
    if skip() {
        return;
    }
    let t = tool(ChildNetworkPolicy::DenyDirect);
    let out = t
        .invoke(serde_json::json!({ "cmd": PROBE }), &ctx(&t, &["python3"]))
        .await
        .expect("invoke");
    // The confined path must actually have been taken (else the floor never ran).
    assert_eq!(
        out["sandbox_kind"], "landlock",
        "the child must be kernel-confined: {out}"
    );
    assert_ne!(
        out["exit_code"], 0,
        "DenyDirect must deny the child's AF_INET socket creation: {out}"
    );
}

#[tokio::test]
async fn shell_tool_deny_direct_denies_a_forked_descendants_socket() {
    if skip() {
        return;
    }
    let t = tool(ChildNetworkPolicy::DenyDirect);
    let out = t
        .invoke(
            serde_json::json!({ "cmd": DESCENDANT_PROBE }),
            &ctx(&t, &["python3"]),
        )
        .await
        .expect("invoke");
    assert_ne!(
        out["exit_code"], 0,
        "DenyDirect must be inherited across fork/exec into a descendant: {out}"
    );
}

#[tokio::test]
async fn shell_tool_landlock_only_default_allows_the_childs_socket() {
    if skip() {
        return;
    }
    // Default policy == LandlockOnly: the control. The same probe SUCCEEDS,
    // proving both that the leak DenyDirect closes is real AND that ordinary
    // behavior is unchanged for callers who don't opt in.
    let t = tool(ChildNetworkPolicy::LandlockOnly);
    let out = t
        .invoke(serde_json::json!({ "cmd": PROBE }), &ctx(&t, &["python3"]))
        .await
        .expect("invoke");
    assert_eq!(
        out["exit_code"], 0,
        "LandlockOnly (default) must leave the child's UDP socket creation open: {out}"
    );
}

#[tokio::test]
async fn shell_tool_deny_direct_leaves_ordinary_non_network_work_unchanged() {
    if skip() {
        return;
    }
    // A non-network command runs normally under DenyDirect — the floor only
    // touches off-box socket creation; stdout capture and the shell path are
    // otherwise unchanged.
    let t = tool(ChildNetworkPolicy::DenyDirect);
    let out = t
        .invoke(
            serde_json::json!({ "cmd": "echo hello-from-confined" }),
            &ctx(&t, &["echo"]),
        )
        .await
        .expect("invoke");
    assert_eq!(out["exit_code"], 0, "ordinary command must run: {out}");
    assert!(
        out["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("hello-from-confined"),
        "stdout must be captured unchanged: {out}"
    );
}
