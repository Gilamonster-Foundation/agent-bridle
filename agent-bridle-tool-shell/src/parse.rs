//! Safe-subset command-line parsing for the confined shell engine (ADR 0005 D3).
//!
//! `agent-bridle` is the **exec funnel**: rather than hand a string to a shell
//! interpreter, the engine parses it itself and runs only what it can confine.
//! This covers **increments 1–2** — a pipeline of simple commands
//! (`a | b | c`) with quoted arguments. Redirections, `&&`/`||`/`;`, globbing
//! and variable expansion are added in later increments (tracked on
//! agent-bridle#34); until then each is refused as [`Refusal::Unsupported`],
//! kept distinct from the [`Refusal::Dynamic`] constructs refused **by design**
//! — command/arithmetic substitution, backticks, subshells: the undecidable
//! interiors ADR 0001 says may never be statically cleared.
//!
//! Quoting is honored, so a metacharacter **inside quotes is a literal
//! argument** — only *unquoted* operators and constructs are recognized. That is
//! the safety property the unit tests pin: `echo "a|b"` is the single-stage argv
//! `["echo", "a|b"]`, while `echo a | b` is the two-stage pipeline
//! `[["echo", "a"], ["b"]]`.

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
    /// this increment (redirections, sequencing, globbing, variable expansion).
    /// Tracked on agent-bridle#34.
    Unsupported(&'static str),
    /// The input could not be parsed (unterminated quote, trailing backslash,
    /// empty command or pipeline stage).
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

/// A parsed pipeline: an ordered list of command stages, each its own argv.
/// A single command (no `|`) is a one-element pipeline.
pub type Pipeline = Vec<Vec<String>>;

/// Parse a `cmd` string into a [`Pipeline`] (one or more `|`-separated command
/// stages), or a [`Refusal`].
///
/// Single quotes are fully literal; double quotes are literal except `$` and a
/// backtick still trigger substitution detection (as in a real shell). An
/// unquoted backslash escapes the next character. An unquoted single `|`
/// separates pipeline stages; every other operator (`&&`, `||`, `;`, `<`, `>`)
/// is [`Refusal::Unsupported`] in this increment, and any substitution
/// (`$(...)`, backticks, `( … )`) is [`Refusal::Dynamic`].
pub fn classify(input: &str) -> Result<Pipeline, Refusal> {
    let mut pipeline: Pipeline = Vec::new();
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
            // ── pipeline stage separator (a single, unquoted `|`) ────────────
            '|' => {
                if chars.peek() == Some(&'|') {
                    return Err(Refusal::Unsupported("logical OR `||`"));
                }
                if has_word {
                    words.push(std::mem::take(&mut cur));
                    has_word = false;
                }
                if words.is_empty() {
                    return Err(Refusal::Malformed(
                        "empty pipeline stage (nothing before `|`)".into(),
                    ));
                }
                pipeline.push(std::mem::take(&mut words));
            }
            // ── operators: supported later, refused (cleanly) for now ───────
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

    // Finalize the trailing stage.
    if has_word {
        words.push(cur);
    }
    if !words.is_empty() {
        pipeline.push(words);
    } else if pipeline.is_empty() {
        return Err(Refusal::Malformed("empty command".into()));
    } else {
        // A `|` with nothing after it.
        return Err(Refusal::Malformed(
            "empty pipeline stage (nothing after `|`)".into(),
        ));
    }
    Ok(pipeline)
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

    /// One command's argv.
    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    /// A single-stage pipeline (the common case).
    fn one(parts: &[&str]) -> Pipeline {
        vec![argv(parts)]
    }

    // ── single commands (increment 1, now one-stage pipelines) ──────────────

    #[test]
    fn simple_command_splits_on_whitespace() {
        assert_eq!(
            classify("echo hi there").unwrap(),
            one(&["echo", "hi", "there"])
        );
    }

    #[test]
    fn collapses_runs_of_whitespace() {
        assert_eq!(classify("  echo\t hi \n").unwrap(), one(&["echo", "hi"]));
    }

    #[test]
    fn single_quotes_are_literal() {
        assert_eq!(classify("echo 'a b'").unwrap(), one(&["echo", "a b"]));
    }

    #[test]
    fn double_quotes_group_words() {
        assert_eq!(classify("echo \"a b\"").unwrap(), one(&["echo", "a b"]));
    }

    #[test]
    fn empty_quotes_produce_an_empty_arg() {
        assert_eq!(classify("echo ''").unwrap(), one(&["echo", ""]));
    }

    #[test]
    fn backslash_escapes_a_space() {
        assert_eq!(classify("echo a\\ b").unwrap(), one(&["echo", "a b"]));
    }

    #[test]
    fn escaped_dollar_is_a_literal_dollar() {
        assert_eq!(classify("echo \\$5").unwrap(), one(&["echo", "$5"]));
        assert_eq!(classify("echo \"\\$5\"").unwrap(), one(&["echo", "$5"]));
    }

    // ── pipelines (increment 2) ─────────────────────────────────────────────

    #[test]
    fn pipeline_splits_into_stages() {
        assert_eq!(
            classify("grep foo | head -n 3").unwrap(),
            vec![argv(&["grep", "foo"]), argv(&["head", "-n", "3"])]
        );
    }

    #[test]
    fn multi_stage_pipeline() {
        assert_eq!(
            classify("a | b | c").unwrap(),
            vec![argv(&["a"]), argv(&["b"]), argv(&["c"])]
        );
    }

    #[test]
    fn pipe_without_surrounding_spaces() {
        assert_eq!(
            classify("grep foo|wc -l").unwrap(),
            vec![argv(&["grep", "foo"]), argv(&["wc", "-l"])]
        );
    }

    #[test]
    fn empty_pipeline_stage_is_malformed() {
        assert!(matches!(classify("| x"), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("x |"), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("a | | b"), Err(Refusal::Malformed(_))));
    }

    // ── the security property: quoted metacharacters are LITERAL ────────────

    #[test]
    fn quoted_pipe_is_a_literal_argument_not_a_separator() {
        // Load-bearing: a `|` inside quotes is one literal arg, NOT a stage split.
        assert_eq!(classify("echo \"a|b\"").unwrap(), one(&["echo", "a|b"]));
        assert_eq!(classify("echo 'a && b'").unwrap(), one(&["echo", "a && b"]));
        assert_eq!(
            classify("grep '$(x)' f").unwrap(),
            one(&["grep", "$(x)", "f"])
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
        // Even downstream of a (now-supported) pipe, a dynamic stage is refused.
        assert!(matches!(
            classify("echo hi | $(evil)"),
            Err(Refusal::Dynamic(_))
        ));
    }

    #[test]
    fn subshell_is_dynamic_refused() {
        assert!(matches!(classify("(echo hi)"), Err(Refusal::Dynamic(_))));
    }

    // ── operators still refused as UNSUPPORTED ──────────────────────────────

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
        assert!(classify("a && b")
            .unwrap_err()
            .to_string()
            .contains("not yet supported"));
    }
}
