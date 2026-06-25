//! Safe-subset command-line parsing for the confined shell engine (ADR 0005 D3).
//!
//! `agent-bridle` is the **exec funnel**: rather than hand a string to a shell
//! interpreter, the engine parses it itself and runs only what it can confine.
//! This covers **increments 1–3** — a pipeline of simple commands (`a | b | c`)
//! with quoted arguments and file redirections (`> out`, `>> out`, `< in`).
//! `&&`/`||`/`;`, globbing and variable expansion are added in later increments
//! (tracked on agent-bridle#34); until then each is refused as
//! [`Refusal::Unsupported`], kept distinct from the [`Refusal::Dynamic`]
//! constructs refused **by design** — command/arithmetic substitution,
//! backticks, subshells: the undecidable interiors ADR 0001 says may never be
//! statically cleared. fd-number redirections (`2>`, `2>&1`) are refused as
//! `Unsupported` for now (a focused follow-up) rather than risk silently
//! mishandling bash's fd-number rules.
//!
//! Quoting is honored, so a metacharacter **inside quotes is a literal
//! argument** — only *unquoted* operators and constructs are recognized:
//! `echo "a|b"` is one argv, `echo ">"` is the literal arg `>`, while
//! `echo a | b` is a two-stage pipeline and `echo hi > out` carries a redirect.

use std::fmt;
use std::iter::Peekable;
use std::mem::take;
use std::str::Chars;

/// Why the confined engine refused to run a `cmd` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Refused **by design** (security): the construct's interior is dynamic and
    /// cannot be statically confined, so the engine never interprets it
    /// (command/arithmetic substitution, backticks, subshells). For a full
    /// shell, use the embedder's unbridled/`--yolo` allowance (ADR 0003 / 0005 D5).
    Dynamic(&'static str),
    /// A construct the safe-subset engine will support but **does not yet** in
    /// this increment (`&&`/`||`/`;`, globbing, variable expansion, fd-number
    /// redirections). Tracked on agent-bridle#34.
    Unsupported(&'static str),
    /// The input could not be parsed (unterminated quote, trailing backslash,
    /// empty command/stage, missing redirection target).
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

/// A file redirection on one command stage. `agent-bridle` performs the open, so
/// each is leash-checked (`fs_write` for stdout, `fs_read` for stdin) before the
/// stage runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redirect {
    /// `> path` (truncate) or `>> path` (append) — stdout (fd 1).
    Stdout { path: String, append: bool },
    /// `< path` — stdin (fd 0).
    Stdin { path: String },
}

/// One command stage: its argv plus any redirections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The program (argv[0]) and arguments.
    pub argv: Vec<String>,
    /// File redirections, in source order (last stdout redirect wins for fd 1).
    pub redirects: Vec<Redirect>,
}

impl Command {
    /// The effective stdin redirect path, if any (last one wins).
    #[must_use]
    pub fn stdin_path(&self) -> Option<&str> {
        self.redirects.iter().rev().find_map(|r| match r {
            Redirect::Stdin { path } => Some(path.as_str()),
            Redirect::Stdout { .. } => None,
        })
    }

    /// The effective stdout redirect (path, append), if any (last one wins).
    #[must_use]
    pub fn stdout_redirect(&self) -> Option<(&str, bool)> {
        self.redirects.iter().rev().find_map(|r| match r {
            Redirect::Stdout { path, append } => Some((path.as_str(), *append)),
            Redirect::Stdin { .. } => None,
        })
    }
}

/// A parsed pipeline: an ordered list of command stages. A single command
/// (no `|`) is a one-element pipeline.
pub type Pipeline = Vec<Command>;

/// Parse a `cmd` string into a [`Pipeline`], or a [`Refusal`].
pub fn classify(input: &str) -> Result<Pipeline, Refusal> {
    let mut chars = input.chars().peekable();
    let mut pipeline: Pipeline = Vec::new();
    let mut argv: Vec<String> = Vec::new();
    let mut redirects: Vec<Redirect> = Vec::new();

    loop {
        skip_whitespace(&mut chars);
        let Some(&c) = chars.peek() else { break };
        match c {
            '|' => {
                chars.next();
                if chars.peek() == Some(&'|') {
                    return Err(Refusal::Unsupported("logical OR `||`"));
                }
                if argv.is_empty() {
                    return Err(Refusal::Malformed(
                        "empty pipeline stage (nothing before `|`)".into(),
                    ));
                }
                pipeline.push(Command {
                    argv: take(&mut argv),
                    redirects: take(&mut redirects),
                });
            }
            '&' => {
                chars.next();
                return Err(Refusal::Unsupported(if chars.peek() == Some(&'&') {
                    "logical AND `&&`"
                } else {
                    "background `&`"
                }));
            }
            ';' => return Err(Refusal::Unsupported("command sequencing `;`")),
            '(' | ')' => return Err(Refusal::Dynamic("subshell `( )`")),
            '`' => return Err(Refusal::Dynamic("command substitution (backticks)")),
            '$' => {
                chars.next();
                return Err(dollar_refusal(chars.peek().copied()));
            }
            '*' | '?' | '[' => return Err(Refusal::Unsupported("filename globbing")),
            '>' => {
                chars.next();
                let append = chars.peek() == Some(&'>');
                if append {
                    chars.next();
                }
                if chars.peek() == Some(&'&') {
                    return Err(Refusal::Unsupported("`>&` (fd duplication)"));
                }
                let path = read_redirect_target(&mut chars)?;
                redirects.push(Redirect::Stdout { path, append });
            }
            '<' => {
                chars.next();
                if chars.peek() == Some(&'<') {
                    return Err(Refusal::Unsupported("heredoc/herestring `<<`"));
                }
                if chars.peek() == Some(&'&') {
                    return Err(Refusal::Unsupported("`<&` (fd duplication)"));
                }
                let path = read_redirect_target(&mut chars)?;
                redirects.push(Redirect::Stdin { path });
            }
            _ => argv.push(read_word(&mut chars)?),
        }
    }

    // Finalize the trailing stage.
    if argv.is_empty() && redirects.is_empty() {
        return if pipeline.is_empty() {
            Err(Refusal::Malformed("empty command".into()))
        } else {
            Err(Refusal::Malformed(
                "empty pipeline stage (nothing after `|`)".into(),
            ))
        };
    }
    if argv.is_empty() {
        return Err(Refusal::Malformed("redirection without a command".into()));
    }
    pipeline.push(Command { argv, redirects });
    Ok(pipeline)
}

/// Consume any run of unquoted whitespace.
fn skip_whitespace(chars: &mut Peekable<Chars>) {
    while matches!(chars.peek(), Some(' ' | '\t' | '\n' | '\r')) {
        chars.next();
    }
}

/// Read the next word (no leading-whitespace skip — the caller does that). Stops
/// at unquoted whitespace or an operator/special char (which the caller then
/// handles). Single quotes are literal; double quotes are literal except `$` and
/// a backtick still trigger substitution detection; an unquoted backslash
/// escapes the next char. A bare digit-word immediately followed by `>`/`<` is a
/// refused fd-number redirection (rather than a silently-mishandled arg).
fn read_word(chars: &mut Peekable<Chars>) -> Result<String, Refusal> {
    let mut cur = String::new();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => break,
            // Operators / specials end the word; the caller decides what to do.
            '|' | '&' | ';' | '<' | '>' | '(' | ')' | '$' | '`' | '*' | '?' | '[' => break,
            '\'' => {
                chars.next();
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => cur.push(ch),
                        None => return Err(Refusal::Malformed("unterminated single quote".into())),
                    }
                }
            }
            '"' => {
                chars.next();
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.peek() {
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
            '\\' => {
                chars.next();
                match chars.next() {
                    Some(n) => cur.push(n),
                    None => return Err(Refusal::Malformed("trailing backslash".into())),
                }
            }
            _ => {
                cur.push(c);
                chars.next();
            }
        }
    }
    // `2>` / `0<` etc.: a bare digit-word touching a redirect operator.
    if !cur.is_empty()
        && cur.bytes().all(|b| b.is_ascii_digit())
        && matches!(chars.peek(), Some('>') | Some('<'))
    {
        return Err(Refusal::Unsupported("fd-number redirection (e.g. `2>`)"));
    }
    Ok(cur)
}

/// Read a redirection target (the word after `>`/`>>`/`<`).
fn read_redirect_target(chars: &mut Peekable<Chars>) -> Result<String, Refusal> {
    skip_whitespace(chars);
    match chars.peek().copied() {
        None | Some('|' | '&' | ';' | '<' | '>' | '(' | ')') => {
            return Err(Refusal::Malformed("missing redirection target".into()))
        }
        _ => {}
    }
    let target = read_word(chars)?;
    if target.is_empty() {
        return Err(Refusal::Malformed("empty redirection target".into()));
    }
    Ok(target)
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
    /// A one-stage pipeline with no redirects.
    fn one(parts: &[&str]) -> Pipeline {
        vec![Command {
            argv: argv(parts),
            redirects: vec![],
        }]
    }
    fn out(path: &str, append: bool) -> Redirect {
        Redirect::Stdout {
            path: path.into(),
            append,
        }
    }
    fn stdin(path: &str) -> Redirect {
        Redirect::Stdin { path: path.into() }
    }

    // ── words, quoting, pipelines (increments 1–2) ──────────────────────────

    #[test]
    fn simple_command() {
        assert_eq!(
            classify("echo hi there").unwrap(),
            one(&["echo", "hi", "there"])
        );
    }

    #[test]
    fn quoting_groups_and_is_literal() {
        assert_eq!(classify("echo 'a b'").unwrap(), one(&["echo", "a b"]));
        assert_eq!(classify("echo \"a b\"").unwrap(), one(&["echo", "a b"]));
        assert_eq!(classify("echo ''").unwrap(), one(&["echo", ""]));
        assert_eq!(classify("echo a\\ b").unwrap(), one(&["echo", "a b"]));
        assert_eq!(classify("echo \\$5").unwrap(), one(&["echo", "$5"]));
    }

    #[test]
    fn pipelines_split_into_stages() {
        assert_eq!(
            classify("grep foo | wc -l").unwrap(),
            vec![
                Command {
                    argv: argv(&["grep", "foo"]),
                    redirects: vec![]
                },
                Command {
                    argv: argv(&["wc", "-l"]),
                    redirects: vec![]
                },
            ]
        );
        assert_eq!(classify("echo \"a|b\"").unwrap(), one(&["echo", "a|b"]));
    }

    // ── redirections (increment 3) ──────────────────────────────────────────

    #[test]
    fn stdout_truncate_and_append() {
        assert_eq!(
            classify("echo hi > out.txt").unwrap(),
            vec![Command {
                argv: argv(&["echo", "hi"]),
                redirects: vec![out("out.txt", false)]
            }]
        );
        assert_eq!(
            classify("echo hi >> log").unwrap(),
            vec![Command {
                argv: argv(&["echo", "hi"]),
                redirects: vec![out("log", true)]
            }]
        );
    }

    #[test]
    fn stdin_redirect() {
        assert_eq!(
            classify("sort < in.txt").unwrap(),
            vec![Command {
                argv: argv(&["sort"]),
                redirects: vec![stdin("in.txt")]
            }]
        );
    }

    #[test]
    fn redirect_without_spaces_and_quoted_target() {
        assert_eq!(
            classify("echo hi>out").unwrap(),
            vec![Command {
                argv: argv(&["echo", "hi"]),
                redirects: vec![out("out", false)]
            }]
        );
        assert_eq!(
            classify("echo hi > \"my file.txt\"").unwrap(),
            vec![Command {
                argv: argv(&["echo", "hi"]),
                redirects: vec![out("my file.txt", false)]
            }]
        );
    }

    #[test]
    fn redirect_within_a_pipeline_stage() {
        assert_eq!(
            classify("grep x < in | wc -l > out").unwrap(),
            vec![
                Command {
                    argv: argv(&["grep", "x"]),
                    redirects: vec![stdin("in")]
                },
                Command {
                    argv: argv(&["wc", "-l"]),
                    redirects: vec![out("out", false)]
                },
            ]
        );
    }

    #[test]
    fn helpers_pick_the_last_redirect() {
        let p = classify("echo hi > a > b").unwrap();
        assert_eq!(p[0].stdout_redirect(), Some(("b", false)));
        assert_eq!(p[0].stdin_path(), None);
    }

    /// A redirection operator INSIDE quotes is a literal argument, not a redirect.
    #[test]
    fn quoted_redirect_operator_is_literal() {
        assert_eq!(classify("echo \">\"").unwrap(), one(&["echo", ">"]));
        assert_eq!(classify("echo \"a > b\"").unwrap(), one(&["echo", "a > b"]));
    }

    // ── refusals around redirections ────────────────────────────────────────

    #[test]
    fn fd_number_and_dup_and_heredoc_are_unsupported() {
        assert!(matches!(classify("echo 2>f"), Err(Refusal::Unsupported(_)))); // fd-number
        assert!(matches!(
            classify("echo x 2>&1"),
            Err(Refusal::Unsupported(_))
        ));
        assert!(matches!(classify("echo >&1"), Err(Refusal::Unsupported(_)))); // >& dup
        assert!(matches!(
            classify("cat <<EOF"),
            Err(Refusal::Unsupported(_))
        )); // heredoc
    }

    #[test]
    fn missing_or_dangling_redirect_targets_are_malformed() {
        assert!(matches!(classify("echo >"), Err(Refusal::Malformed(_))));
        assert!(matches!(
            classify("echo > | wc"),
            Err(Refusal::Malformed(_))
        ));
        assert!(matches!(classify("> out"), Err(Refusal::Malformed(_)))); // no command
    }

    // ── still-refused operators & dynamic constructs ────────────────────────

    #[test]
    fn operators_and_dynamic_still_refused() {
        assert!(matches!(classify("a && b"), Err(Refusal::Unsupported(_))));
        assert!(matches!(classify("a || b"), Err(Refusal::Unsupported(_))));
        assert!(matches!(classify("a; b"), Err(Refusal::Unsupported(_))));
        assert!(matches!(classify("ls *.rs"), Err(Refusal::Unsupported(_))));
        assert!(matches!(
            classify("echo $HOME"),
            Err(Refusal::Unsupported(_))
        ));
        assert!(matches!(classify("echo $(id)"), Err(Refusal::Dynamic(_))));
        assert!(matches!(classify("echo `id`"), Err(Refusal::Dynamic(_))));
        assert!(matches!(classify("(echo hi)"), Err(Refusal::Dynamic(_))));
        assert!(matches!(
            classify("echo hi | $(evil)"),
            Err(Refusal::Dynamic(_))
        ));
    }

    // ── malformed input ─────────────────────────────────────────────────────

    #[test]
    fn empty_and_unterminated_are_malformed() {
        assert!(matches!(classify("   "), Err(Refusal::Malformed(_))));
        assert!(matches!(classify(""), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("echo 'oops"), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("x |"), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("| x"), Err(Refusal::Malformed(_))));
    }

    #[test]
    fn refusal_display_is_categorized() {
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
