//! `--insecure` per-command approval over the controlling terminal.
//!
//! CRITICAL: approval is read from `/dev/tty`, NEVER stdin. The MCP server's
//! stdin is the JSON-RPC stream; reading approval from it would consume protocol
//! traffic and could be spoofed by the very model whose command we are gating.
//! `/dev/tty` is the operator's controlling terminal, independent of the
//! redirected stdio. If `/dev/tty` cannot be opened (no controlling terminal —
//! e.g. a daemon or CI), we **deny**: fail-closed.

use std::io::{BufRead, BufReader, Write};

use agent_bridle::ApprovalHook;

/// Prompts the operator on `/dev/tty` for each command an UNCONFINED
/// [`ShellTool`](agent_bridle::ShellTool) is about to run. Default-deny.
pub struct TtyApprover;

impl ApprovalHook for TtyApprover {
    fn approve(&self, command: &str) -> bool {
        approve_on_tty(command).unwrap_or(false)
    }
}

/// Open `/dev/tty`, print the command + prompt, read one line, and return
/// whether the operator approved (only `y`/`yes`, case-insensitive — anything
/// else, EOF, or any I/O error denies). Returns `None` on an I/O error so the
/// caller fails closed.
fn approve_on_tty(command: &str) -> Option<bool> {
    // Read + write the controlling terminal directly — not stdin/stdout.
    let mut tty_w = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let tty_r = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .ok()?;

    write!(
        tty_w,
        "\n[agent-bridle --insecure] UNCONFINED command requested:\n  {command}\nallow? [y/N] "
    )
    .ok()?;
    tty_w.flush().ok()?;

    let mut line = String::new();
    BufReader::new(tty_r).read_line(&mut line).ok()?;
    let answer = line.trim().to_ascii_lowercase();
    Some(answer == "y" || answer == "yes")
}
