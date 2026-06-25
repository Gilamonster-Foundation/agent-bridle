//! Safe-subset command-line parsing for the confined shell engine (ADR 0005 D3).
//!
//! `agent-bridle` is the **exec funnel**: rather than hand a string to a shell
//! interpreter, the engine parses it itself and runs only what it can confine.
//! This covers **increments 1–4** — a sequence of pipelines joined by `&&`,
//! `||` and `;`, where each pipeline is simple commands (`a | b | c`) with quoted
//! arguments and file redirections (`> out`, `>> out`, `< in`). Globbing and
//! variable/parameter expansion are added in a later increment (tracked on
//! agent-bridle#34); until then each is refused as [`Refusal::Unsupported`], kept
//! distinct from the [`Refusal::Dynamic`] constructs refused **by design** —
//! command/arithmetic substitution, backticks, subshells: the undecidable
//! interiors ADR 0001 says may never be statically cleared. fd-number
//! redirections (`2>`, `2>&1`) are refused as `Unsupported` for now (a focused
//! follow-up) rather than risk silently mishandling bash's fd-number rules.
//!
//! Quoting is honored, so a metacharacter **inside quotes is a literal
//! argument** — only *unquoted* operators and constructs are recognized:
//! `echo "a&&b"` is one argv, while `a && b` is two pipelines joined by `&&`.

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
    /// this increment (globbing, variable expansion, fd-number redirections).
    /// Tracked on agent-bridle#34.
    Unsupported(&'static str),
    /// The input could not be parsed (unterminated quote, trailing backslash,
    /// empty command/stage, missing redirection target, dangling separator).
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

/// A pipeline: one or more `|`-joined command stages.
pub type Pipeline = Vec<Command>;

/// How a pipeline is gated by the *previous* pipeline's exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sep {
    /// `;` — run unconditionally. (The first pipeline always carries `Seq`.)
    Seq,
    /// `&&` — run only if the previous status was success (0).
    And,
    /// `||` — run only if the previous status was failure (non-0).
    Or,
}

/// One step of a [`Script`]: a pipeline plus the separator that gates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptItem {
    /// The separator preceding this pipeline (the first item's is [`Sep::Seq`]).
    pub sep: Sep,
    /// The pipeline to (conditionally) run.
    pub pipeline: Pipeline,
}

/// A parsed command line: a sequence of pipelines joined by `&&`/`||`/`;`.
pub type Script = Vec<ScriptItem>;

/// Parse a `cmd` string into a [`Script`], or a [`Refusal`].
pub fn classify(input: &str) -> Result<Script, Refusal> {
    let mut chars = input.chars().peekable();
    let mut script: Script = Vec::new();
    let mut pending_sep = Sep::Seq; // separator for the NEXT finalized pipeline
    let mut stages: Vec<Command> = Vec::new(); // current pipeline's stages
    let mut argv: Vec<String> = Vec::new(); // current stage's argv
    let mut redirects: Vec<Redirect> = Vec::new(); // current stage's redirects

    loop {
        skip_whitespace(&mut chars);
        let Some(&c) = chars.peek() else { break };
        match c {
            '|' => {
                chars.next();
                if chars.peek() == Some(&'|') {
                    chars.next();
                    push_pipeline(
                        &mut script,
                        &mut stages,
                        &mut argv,
                        &mut redirects,
                        &mut pending_sep,
                        Sep::Or,
                    )?;
                } else {
                    // Pipe: finalize the current stage into the current pipeline.
                    if argv.is_empty() {
                        return Err(Refusal::Malformed(
                            "empty pipeline stage (nothing before `|`)".into(),
                        ));
                    }
                    stages.push(Command {
                        argv: take(&mut argv),
                        redirects: take(&mut redirects),
                    });
                }
            }
            '&' => {
                chars.next();
                if chars.peek() == Some(&'&') {
                    chars.next();
                    push_pipeline(
                        &mut script,
                        &mut stages,
                        &mut argv,
                        &mut redirects,
                        &mut pending_sep,
                        Sep::And,
                    )?;
                } else {
                    return Err(Refusal::Unsupported("background `&`"));
                }
            }
            ';' => {
                chars.next();
                push_pipeline(
                    &mut script,
                    &mut stages,
                    &mut argv,
                    &mut redirects,
                    &mut pending_sep,
                    Sep::Seq,
                )?;
            }
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

    // Finalize the trailing pipeline (no following separator).
    match finalize_pipeline(&mut stages, &mut argv, &mut redirects)? {
        Some(pipeline) => script.push(ScriptItem {
            sep: pending_sep,
            pipeline,
        }),
        None => {
            if script.is_empty() {
                return Err(Refusal::Malformed("empty command".into()));
            }
            if !matches!(pending_sep, Sep::Seq) {
                return Err(Refusal::Malformed(
                    "expected a command after `&&` or `||`".into(),
                ));
            }
            // A trailing `;` is fine.
        }
    }
    Ok(script)
}

/// Finalize the current stage + pipeline and push it to the script under
/// `pending_sep`, then arm `pending_sep` for the next pipeline. An empty pipeline
/// around a separator is malformed.
fn push_pipeline(
    script: &mut Script,
    stages: &mut Vec<Command>,
    argv: &mut Vec<String>,
    redirects: &mut Vec<Redirect>,
    pending_sep: &mut Sep,
    next_sep: Sep,
) -> Result<(), Refusal> {
    match finalize_pipeline(stages, argv, redirects)? {
        Some(pipeline) => {
            script.push(ScriptItem {
                sep: *pending_sep,
                pipeline,
            });
            *pending_sep = next_sep;
            Ok(())
        }
        None => Err(Refusal::Malformed(
            "empty command around a separator (`&&`/`||`/`;`)".into(),
        )),
    }
}

/// Finalize the current stage into the current pipeline and return the pipeline.
/// `Ok(None)` means the pipeline was entirely empty (no stages/argv/redirects).
/// A `|` with no following stage, or a redirect with no command, is malformed.
fn finalize_pipeline(
    stages: &mut Vec<Command>,
    argv: &mut Vec<String>,
    redirects: &mut Vec<Redirect>,
) -> Result<Option<Pipeline>, Refusal> {
    if argv.is_empty() {
        if !stages.is_empty() {
            return Err(Refusal::Malformed(
                "empty pipeline stage (nothing after `|`)".into(),
            ));
        }
        if !redirects.is_empty() {
            return Err(Refusal::Malformed("redirection without a command".into()));
        }
        return Ok(None);
    }
    stages.push(Command {
        argv: take(argv),
        redirects: take(redirects),
    });
    Ok(Some(take(stages)))
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
    fn stage(parts: &[&str]) -> Command {
        Command {
            argv: argv(parts),
            redirects: vec![],
        }
    }
    /// A single-pipeline, single-stage script with no redirects.
    fn one(parts: &[&str]) -> Script {
        vec![ScriptItem {
            sep: Sep::Seq,
            pipeline: vec![stage(parts)],
        }]
    }
    fn item(sep: Sep, stages: Vec<Command>) -> ScriptItem {
        ScriptItem {
            sep,
            pipeline: stages,
        }
    }

    // ── words / quoting / pipelines / redirects (increments 1–3) ────────────

    #[test]
    fn simple_command_and_quoting() {
        assert_eq!(
            classify("echo hi there").unwrap(),
            one(&["echo", "hi", "there"])
        );
        assert_eq!(classify("echo 'a b'").unwrap(), one(&["echo", "a b"]));
        assert_eq!(classify("echo \"a|b\"").unwrap(), one(&["echo", "a|b"]));
        assert_eq!(classify("echo \"a&&b\"").unwrap(), one(&["echo", "a&&b"]));
    }

    #[test]
    fn pipeline_and_redirect_still_parse() {
        assert_eq!(
            classify("grep foo | wc -l").unwrap(),
            vec![item(
                Sep::Seq,
                vec![stage(&["grep", "foo"]), stage(&["wc", "-l"])]
            )]
        );
        let p = classify("echo hi > out").unwrap();
        assert_eq!(p[0].pipeline[0].stdout_redirect(), Some(("out", false)));
    }

    // ── sequencing (increment 4) ────────────────────────────────────────────

    #[test]
    fn and_or_seq_separators() {
        assert_eq!(
            classify("a && b").unwrap(),
            vec![
                item(Sep::Seq, vec![stage(&["a"])]),
                item(Sep::And, vec![stage(&["b"])])
            ]
        );
        assert_eq!(
            classify("a || b").unwrap(),
            vec![
                item(Sep::Seq, vec![stage(&["a"])]),
                item(Sep::Or, vec![stage(&["b"])])
            ]
        );
        assert_eq!(
            classify("a ; b").unwrap(),
            vec![
                item(Sep::Seq, vec![stage(&["a"])]),
                item(Sep::Seq, vec![stage(&["b"])])
            ]
        );
    }

    #[test]
    fn mixed_separators_and_pipelines() {
        // `a | b && c ; d` → [ {Seq, a|b}, {And, c}, {Seq, d} ]
        assert_eq!(
            classify("a | b && c ; d").unwrap(),
            vec![
                item(Sep::Seq, vec![stage(&["a"]), stage(&["b"])]),
                item(Sep::And, vec![stage(&["c"])]),
                item(Sep::Seq, vec![stage(&["d"])]),
            ]
        );
    }

    #[test]
    fn trailing_semicolon_is_ok_but_dangling_andor_is_not() {
        assert_eq!(
            classify("a ; b ;").unwrap(),
            vec![
                item(Sep::Seq, vec![stage(&["a"])]),
                item(Sep::Seq, vec![stage(&["b"])])
            ]
        );
        assert!(matches!(classify("a &&"), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("a ||"), Err(Refusal::Malformed(_))));
    }

    #[test]
    fn leading_or_doubled_separators_are_malformed() {
        assert!(matches!(classify("; a"), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("&& a"), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("a ; ; b"), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("a && | b"), Err(Refusal::Malformed(_))));
    }

    // ── refusals ────────────────────────────────────────────────────────────

    #[test]
    fn dynamic_and_unsupported_and_fd_still_refused() {
        assert!(matches!(classify("echo $(id)"), Err(Refusal::Dynamic(_))));
        assert!(matches!(classify("echo `id`"), Err(Refusal::Dynamic(_))));
        assert!(matches!(classify("(echo hi)"), Err(Refusal::Dynamic(_))));
        assert!(matches!(classify("ls *.rs"), Err(Refusal::Unsupported(_))));
        assert!(matches!(
            classify("echo $HOME"),
            Err(Refusal::Unsupported(_))
        ));
        assert!(matches!(classify("echo 2>f"), Err(Refusal::Unsupported(_))));
        assert!(matches!(classify("echo x &"), Err(Refusal::Unsupported(_)))); // background
                                                                               // A dynamic stage anywhere in the sequence is refused.
        assert!(matches!(
            classify("echo ok && $(evil)"),
            Err(Refusal::Dynamic(_))
        ));
    }

    #[test]
    fn empty_and_unterminated_are_malformed() {
        assert!(matches!(classify("   "), Err(Refusal::Malformed(_))));
        assert!(matches!(classify(""), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("echo 'oops"), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("x |"), Err(Refusal::Malformed(_))));
    }
}
