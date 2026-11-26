#![cfg(feature = "brush")]

use agent_bridle_tool_shell::literal_shell_word;

#[test]
fn literal_arguments_are_not_classified_as_commands() {
    // Cases carried by newt-agent#3093's gh_read tests and inspection parity corpus.
    for (source, expected) in [
        ("o/r", "o/r"),
        ("owner/r", "owner/r"),
        ("otherhost/o/r", "otherhost/o/r"),
        ("done", "done"),
        ("if", "if"),
        ("sh", "sh"),
        ("'two words'", "two words"),
        (r#""two words""#, "two words"),
        (r"two\ words", "two words"),
        ("'$(touch file)'", "$(touch file)"),
        ("''", ""),
        (r#""""#, ""),
        (r"\$HOME", "$HOME"),
        (r"\*.rs", "*.rs"),
        (r#""*.rs""#, "*.rs"),
        ("'a'\"b\"c", "abc"),
        ("'café ü'", "café ü"),
    ] {
        assert_eq!(literal_shell_word(source).unwrap(), expected, "{source:?}");
    }
}

#[test]
fn literal_argument_refuses_extra_source_expansion_and_shell_syntax() {
    for source in [
        "",
        " ",
        " x",
        "x ",
        "x\n",
        "a b",
        "x; id",
        "x;",
        "x # comment",
        "x > file",
        "x 2>&1",
        "x < file",
        "$(id)",
        "$HOME",
        "${HOME}",
        "*.rs",
        "?.rs",
        "[ab].rs",
        "{a,b}",
        "{1..3}",
        "x\ny",
        "a && b",
        "a || b",
        "a | b",
        "a &",
        "~",
        "`id`",
        "\"$(id)\"",
        "$((1 + 2))",
        "<(id)",
        "(id)",
        "x; if true; then id; fi",
        "'unterminated",
    ] {
        assert!(literal_shell_word(source).is_err(), "{source:?}");
    }
    assert!(literal_shell_word(&"x".repeat(32 * 1024 + 1)).is_err());
}

#[test]
fn literal_argument_never_executes_a_substitution() {
    let marker = std::env::temp_dir().join(format!(
        "agent-bridle-literal-word-no-exec-{}",
        std::process::id()
    ));
    assert!(!marker.exists());
    for source in [
        format!("$(touch '{}')", marker.display()),
        format!("`touch '{}'`", marker.display()),
    ] {
        assert!(literal_shell_word(&source).is_err());
        assert!(!marker.exists(), "literal argument parsing executed source");
    }
}
