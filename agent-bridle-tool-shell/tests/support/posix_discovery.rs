use agent_bridle_core::{Caveats, Gate, Tool};
use std::os::unix::fs::PermissionsExt;

pub async fn exercise(tool: &dyn Tool) {
    let dir = std::env::temp_dir().join(format!("ab-posix-discovery-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    for name in ["which", "probe target"] {
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\nprintf 'external utility ran\\n'\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let cx = Gate::new(0).authorize(tool, &Caveats::top()).unwrap();
    let minimal_path = dir.to_str().unwrap();
    let cases = [
        ("", "which printf", "printf\n".to_string()),
        (
            minimal_path,
            "which 'probe target'",
            format!("{minimal_path}/probe target\n"),
        ),
        (minimal_path, "which printf", "printf\n".to_string()),
        (
            "",
            "which() { printf 'user:%s\\n' \"$1\"; }; which custom",
            "user:custom\n".to_string(),
        ),
        (
            "",
            "command() { printf 'user-command\\n'; }; which printf",
            "user-command\n".to_string(),
        ),
    ];
    let mut outputs = Vec::new();
    for (path, command, expected) in cases {
        let out = tool
            .invoke(
                serde_json::json!({"cmd": command, "env": {"PATH": path}}),
                &cx,
            )
            .await
            .unwrap();
        outputs.push((command, expected, out));
    }
    let missing = tool
        .invoke(
            serde_json::json!({
                "cmd": "which bridle-command-that-does-not-exist", "env": {"PATH": ""}
            }),
            &cx,
        )
        .await
        .unwrap();
    // Preserve each interpreter's command -v semantics for user functions.
    let mut function_results = Vec::new();
    for lookup in ["command -v target", "which target"] {
        function_results.push(
            tool.invoke(
                serde_json::json!({
                    "cmd": format!("target() {{ :; }}; {lookup}"), "env": {"PATH": ""}
                }),
                &cx,
            )
            .await
            .unwrap(),
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
    for field in ["exit_code", "stdout", "stderr"] {
        assert_eq!(function_results[0][field], function_results[1][field]);
    }
    for (command, expected, out) in outputs {
        assert_eq!(out["exit_code"], 0, "{command}: {out}");
        assert_eq!(out["stdout"], expected, "{command}: {out}");
        assert_eq!(out["stderr"], "", "{command}: {out}");
    }
    assert_ne!(missing["exit_code"], 0, "{missing}");
}

// Host callers select bash for this check: POSIX does not require LINENO and
// Linux's default /bin/sh (dash) leaves it unset.
pub async fn exercise_line_numbers(tool: &dyn Tool) {
    let cx = Gate::new(0).authorize(tool, &Caveats::top()).unwrap();
    for (command, expected) in [
        ("printf '%s\\n' \"$LINENO\"", "1\n"),
        ("# leading comment\nprintf '%s\\n' \"$LINENO\"", "2\n"),
        ("\nprintf '%s\\n' \"$LINENO\"", "2\n"),
        (
            "cat <<'EOF'\nbody\nEOF\nprintf '%s\\n' \"$LINENO\"",
            "body\n4\n",
        ),
    ] {
        let out = tool
            .invoke(serde_json::json!({"cmd": command}), &cx)
            .await
            .unwrap();
        assert_eq!(out["exit_code"], 0, "{command}: {out}");
        assert_eq!(out["stdout"], expected, "{command}: {out}");
        assert_eq!(out["stderr"], "", "{command}: {out}");
    }
}
