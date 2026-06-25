//! Safe-subset command-line parsing for the confined shell engine (ADR 0005 D3).
//!
//! `agent-bridle` is the **exec funnel**: rather than hand a string to a shell
//! interpreter, the engine parses it itself and runs only what it can confine.
//! This is **increment 1** — a single command with quoted arguments. Pipelines,
//! redirections, `&&`/`||`/`;`, globbing and variable expansion are added in
//! later increments (tracked on agent-bridle#34); until then each is refused as
//! [`Refusal::Unsupported`], kept distinct from the [`Refusal::Dynamic`]
//! constructs refused **by design** — command/arithmetic substitution,
//! backticks, subshells: the undecidable interiors ADR 0001 says may never be
//! statically cleared.
//!
//! Quoting is honored, so a metacharacter **inside quotes is a literal
//! argument** — only *unquoted* operators and constructs are recognized. That is
//! the safety property the unit tests pin: `echo "a|b"` is the two-element argv
//! `["echo", "a|b"]`, while `echo a|b` is refused.

use std::fmt;

/// Why the confined engine refused to run a `cmd` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Refused **by design** (security): the construct's interior is dynamic and
    /// cannot be statically confined, so the engine never interprets it
    /// (command/arithmetic substitution, backticks, subshells). For a full
    /// shell, use the embedder's unbridled/`--yolo` allowance (ADR 0003 / 0005 D5).
    Dynamic(&'static str),
    /// A construct the safe-subset engine will support but **does not yet** in
    /// this increment (pipelines, redirections, sequencing, globbing, variable
    /// expansion). Tracked on agent-bridle#34.
    Unsupported(&'static str),
    /// The input could not be parsed (unterminated quote, trailing backslash,
    /// empty command).
    Malformed(String),
}

impl Refusal {
    /// A short label for the offending construct (the envelope `target`).
    #[must_use]
    pub fn construct(&self) -> String {
        match self {
            Self::Dynamic(c) | Self::Unsupported(c) => (*c).to_string(),
            Self::Malformed(_) => "malformed input".to_string(),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dynamic(c) => write!(
                f,
                "refused by design: {c} is a dynamic construct the confined shell does not \
                 interpret (use the embedder's unbridled/--yolo path for a full shell)"
            ),
            Self::Unsupported(c) => write!(
                f,
                "not yet supported by the confined shell engine: {c} (tracked on agent-bridle#34)"
            ),
            Self::Malformed(why) => write!(f, "malformed command: {why}"),
        }
    }
}

/// Parse a `cmd` string into a **single command's argv**, or a [`Refusal`].
///
/// Single quotes are fully literal; double quotes are literal except `$` and a
/// backtick still trigger substitution detection (as in a real shell). An
/// unquoted backslash escapes the next character. Any *unquoted* operator
/// (`|`, `&&`, `;`, `<`, `>`) is [`Refusal::Unsupported`] in this increment, and
/// any substitution (`$(...)`, backticks, `( … )`) is [`Refusal::Dynamic`].
pub fn classify(input: &str) -> Result<Vec<String>, Refusal> {
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut has_word = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            // ── single quotes: fully literal ────────────────────────────────
            '\'' => {
                has_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => cur.push(ch),
                        None => return Err(Refusal::Malformed("unterminated single quote".into())),
                    }
                }
            }
            // ── double quotes: literal except $ / backtick still expand ──────
            '"' => {
                has_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.peek() {
                            // In double quotes, backslash escapes only these.
                            Some(&n) if matches!(n, '"' | '\\' | '$' | '`') => {
                                cur.push(n);
                                chars.next();
                            }
                            _ => cur.push('\\'),
                        },
                        Some('$') => return Err(dollar_refusal(chars.peek().copied())),
                        Some('`') => {
                            return Err(Refusal::Dynamic("command substitution (backticks)"))
                        }
                        Some(ch) => cur.push(ch),
                        None => return Err(Refusal::Malformed("unterminated double quote".into())),
                    }
                }
            }
            // ── unquoted backslash escapes the next char (literal) ──────────
            '\\' => match chars.next() {
                Some(n) => {
                    cur.push(n);
                    has_word = true;
                }
                None => return Err(Refusal::Malformed("trailing backslash".into())),
            },
            // ── whitespace separates words ──────────────────────────────────
            ' ' | '\t' | '\n' | '\r' => {
                if has_word {
                    words.push(std::mem::take(&mut cur));
                    has_word = false;
                }
            }
            // ── operators: supported later, refused (cleanly) for now ───────
            '|' => {
                return Err(Refusal::Unsupported(if chars.peek() == Some(&'|') {
                    "logical OR `||`"
                } else {
                    "pipeline `|`"
                }))
            }
            '&' => {
                return Err(Refusal::Unsupported(if chars.peek() == Some(&'&') {
                    "logical AND `&&`"
                } else {
                    "background `&`"
                }))
            }
            ';' => return Err(Refusal::Unsupported("command sequencing `;`")),
            '<' => return Err(Refusal::Unsupported("input redirection `<`")),
            '>' => return Err(Refusal::Unsupported("output redirection `>`")),
            '*' | '?' => return Err(Refusal::Unsupported("filename globbing")),
            '[' => return Err(Refusal::Unsupported("filename globbing (`[`)")),
            // ── dynamic constructs: refused by design ───────────────────────
            '(' | ')' => return Err(Refusal::Dynamic("subshell `( )`")),
            '`' => return Err(Refusal::Dynamic("command substitution (backticks)")),
            '$' => return Err(dollar_refusal(chars.peek().copied())),
            // ── ordinary character ──────────────────────────────────────────
            _ => {
                cur.push(c);
                has_word = true;
            }
        }
    }

    if has_word {
        words.push(cur);
    }
    if words.is_empty() {
        return Err(Refusal::Malformed("empty command".into()));
    }
    Ok(words)
}

/// Classify a `$`: `$(` is command/arithmetic substitution (dynamic, refused by
/// design); anything else is variable/parameter expansion (unsupported for now,
/// escapable as `\$`).
fn dollar_refusal(next: Option<char>) -> Refusal {
    match next {
        Some('(') => Refusal::Dynamic("command/arithmetic substitution `$(`"),
        _ => Refusal::Unsupported("variable expansion `$`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    // ── the safe argv cases ─────────────────────────────────────────────────

    #[test]
    fn simple_command_splits_on_whitespace() {
        assert_eq!(
            classify("echo hi there").unwrap(),
            argv(&["echo", "hi", "there"])
        );
    }

    #[test]
    fn collapses_runs_of_whitespace() {
        assert_eq!(classify("  echo\t hi \n").unwrap(), argv(&["echo", "hi"]));
    }

    #[test]
    fn single_quotes_are_literal() {
        assert_eq!(classify("echo 'a b'").unwrap(), argv(&["echo", "a b"]));
    }

    #[test]
    fn double_quotes_group_words() {
        assert_eq!(classify("echo \"a b\"").unwrap(), argv(&["echo", "a b"]));
    }

    #[test]
    fn empty_quotes_produce_an_empty_arg() {
        assert_eq!(classify("echo ''").unwrap(), argv(&["echo", ""]));
    }

    #[test]
    fn backslash_escapes_a_space() {
        assert_eq!(classify("echo a\\ b").unwrap(), argv(&["echo", "a b"]));
    }

    #[test]
    fn escaped_dollar_is_a_literal_dollar() {
        // The escape hatch for a literal `$`: refusal of bare `$` is escapable.
        assert_eq!(classify("echo \\$5").unwrap(), argv(&["echo", "$5"]));
        assert_eq!(classify("echo \"\\$5\"").unwrap(), argv(&["echo", "$5"]));
    }

    // ── the security property: quoted metacharacters are LITERAL ────────────

    #[test]
    fn quoted_pipe_is_a_literal_argument_not_an_operator() {
        // Load-bearing: a metacharacter inside quotes must NOT be treated as an
        // operator. `echo "a|b"` is a single literal arg, not a refused pipeline.
        assert_eq!(classify("echo \"a|b\"").unwrap(), argv(&["echo", "a|b"]));
        assert_eq!(
            classify("echo 'a && b'").unwrap(),
            argv(&["echo", "a && b"])
        );
        assert_eq!(
            classify("grep '$(x)' f").unwrap(),
            argv(&["grep", "$(x)", "f"])
        );
    }

    // ── dynamic constructs refused BY DESIGN ────────────────────────────────

    #[test]
    fn command_substitution_is_dynamic_refused() {
        assert!(matches!(
            classify("echo $(whoami)"),
            Err(Refusal::Dynamic(_))
        ));
        assert!(matches!(
            classify("echo `whoami`"),
            Err(Refusal::Dynamic(_))
        ));
        assert!(matches!(
            classify("echo \"$(id)\""),
            Err(Refusal::Dynamic(_))
        ));
    }

    #[test]
    fn subshell_is_dynamic_refused() {
        assert!(matches!(classify("(echo hi)"), Err(Refusal::Dynamic(_))));
    }

    // ── operators refused as UNSUPPORTED (this increment) ───────────────────

    #[test]
    fn pipeline_is_unsupported_and_the_second_command_never_runs() {
        // The whole string is refused before any argv is produced, so `rm`
        // downstream of the pipe is never reachable.
        assert!(matches!(
            classify("echo a | rm -rf x"),
            Err(Refusal::Unsupported(_))
        ));
    }

    #[test]
    fn logical_and_sequencing_redirection_globbing_are_unsupported() {
        assert!(matches!(classify("a && b"), Err(Refusal::Unsupported(_))));
        assert!(matches!(classify("a || b"), Err(Refusal::Unsupported(_))));
        assert!(matches!(
            classify("echo a; rm b"),
            Err(Refusal::Unsupported(_))
        ));
        assert!(matches!(
            classify("echo hi > f"),
            Err(Refusal::Unsupported(_))
        ));
        assert!(matches!(classify("cat < f"), Err(Refusal::Unsupported(_))));
        assert!(matches!(classify("ls *.rs"), Err(Refusal::Unsupported(_))));
        assert!(matches!(
            classify("echo $HOME"),
            Err(Refusal::Unsupported(_))
        ));
    }

    // ── malformed input ─────────────────────────────────────────────────────

    #[test]
    fn empty_command_is_malformed() {
        assert!(matches!(classify("   "), Err(Refusal::Malformed(_))));
        assert!(matches!(classify(""), Err(Refusal::Malformed(_))));
    }

    #[test]
    fn unterminated_quotes_are_malformed() {
        assert!(matches!(classify("echo 'oops"), Err(Refusal::Malformed(_))));
        assert!(matches!(
            classify("echo \"oops"),
            Err(Refusal::Malformed(_))
        ));
    }

    #[test]
    fn refusal_display_is_legible_and_categorized() {
        assert!(classify("echo $(x)")
            .unwrap_err()
            .to_string()
            .contains("refused by design"));
        assert!(classify("a | b")
            .unwrap_err()
            .to_string()
            .contains("not yet supported"));
    }
}
