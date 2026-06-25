//! Safe-subset command-line parsing for the confined shell engine (ADR 0005 D3).
//!
//! `agent-bridle` is the **exec funnel**: rather than hand a string to a shell
//! interpreter, the engine parses it itself and runs only what it can confine.
//! This covers **increments 1–5** — a sequence of pipelines joined by `&&`,
//! `||` and `;`, each pipeline simple commands (`a | b | c`) with quoted
//! arguments, file redirections (`> out`, `>> out`, `< in`), and **filename
//! globbing** (`*`, `?`, `[…]`). The parser only *marks* an argument as a glob
//! ([`Arg::Glob`]); expansion (a filesystem read) is leash-checked and performed
//! by the executor. Variable/parameter expansion is added in a later increment
//! (tracked on agent-bridle#34); until then `$` is refused as
//! [`Refusal::Unsupported`], kept distinct from the [`Refusal::Dynamic`]
//! constructs refused **by design** — command/arithmetic substitution,
//! backticks, subshells: the undecidable interiors ADR 0001 says may never be
//! statically cleared. fd-number redirections (`2>`, `2>&1`) are refused as
//! `Unsupported` for now (a focused follow-up).
//!
//! Quoting is honored, so a metacharacter **inside quotes is a literal
//! argument** — only *unquoted* operators and constructs are recognized:
//! `echo "a*b"` is one literal arg, while `echo a*` is a glob and `a && b` is two
//! pipelines joined by `&&`.

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
    /// this increment (variable expansion, fd-number redirections). Tracked on
    /// agent-bridle#34.
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

/// One argument word: a literal, or a glob pattern to be expanded by the
/// executor (a filesystem read, leash-checked first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// A literal word (quoting already resolved).
    Lit(String),
    /// A word containing unquoted `*`/`?`/`[…]` — a glob pattern.
    Glob(String),
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

/// One command stage: its argv (literals + globs) plus any redirections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The program (argv[0]) and arguments, each a literal or a glob.
    pub argv: Vec<Arg>,
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
    let mut argv: Vec<Arg> = Vec::new(); // current stage's args
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
            _ => {
                let (word, is_glob) = read_word(&mut chars)?;
                argv.push(if is_glob {
                    Arg::Glob(word)
                } else {
                    Arg::Lit(word)
                });
            }
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
/// `pending_sep`, then arm `pending_sep` for the next pipeline.
fn push_pipeline(
    script: &mut Script,
    stages: &mut Vec<Command>,
    argv: &mut Vec<Arg>,
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
/// `Ok(None)` means the pipeline was entirely empty.
fn finalize_pipeline(
    stages: &mut Vec<Command>,
    argv: &mut Vec<Arg>,
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

/// Read the next word (no leading-whitespace skip — the caller does that).
/// Returns the word and whether it contained an *unquoted* glob metacharacter
/// (`*`/`?`/`[`). Stops at unquoted whitespace or an operator char. Single quotes
/// are literal; double quotes are literal except `$`/backtick still trigger
/// substitution detection; an unquoted backslash escapes the next char. A bare
/// digit-word immediately followed by `>`/`<` is a refused fd-number redirection.
fn read_word(chars: &mut Peekable<Chars>) -> Result<(String, bool), Refusal> {
    let mut cur = String::new();
    let mut is_glob = false;
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => break,
            // Operators / substitution starts end the word; the caller handles them.
            '|' | '&' | ';' | '<' | '>' | '(' | ')' | '$' | '`' => break,
            // Unquoted glob metacharacters: part of the word, and mark it a glob.
            '*' | '?' | '[' => {
                cur.push(c);
                chars.next();
                is_glob = true;
            }
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
        && !is_glob
        && cur.bytes().all(|b| b.is_ascii_digit())
        && matches!(chars.peek(), Some('>') | Some('<'))
    {
        return Err(Refusal::Unsupported("fd-number redirection (e.g. `2>`)"));
    }
    Ok((cur, is_glob))
}

/// Read a redirection target (the word after `>`/`>>`/`<`). The target is taken
/// literally (redirect targets are not globbed in this engine).
fn read_redirect_target(chars: &mut Peekable<Chars>) -> Result<String, Refusal> {
    skip_whitespace(chars);
    match chars.peek().copied() {
        None | Some('|' | '&' | ';' | '<' | '>' | '(' | ')') => {
            return Err(Refusal::Malformed("missing redirection target".into()))
        }
        _ => {}
    }
    let (target, _is_glob) = read_word(chars)?;
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

    fn lit(s: &str) -> Arg {
        Arg::Lit(s.to_string())
    }
    fn glob(s: &str) -> Arg {
        Arg::Glob(s.to_string())
    }
    fn stage(args: Vec<Arg>) -> Command {
        Command {
            argv: args,
            redirects: vec![],
        }
    }
    fn lits(parts: &[&str]) -> Command {
        stage(parts.iter().map(|s| lit(s)).collect())
    }
    /// A single-pipeline, single-stage, all-literal script.
    fn one(parts: &[&str]) -> Script {
        vec![ScriptItem {
            sep: Sep::Seq,
            pipeline: vec![lits(parts)],
        }]
    }

    // ── words / quoting / pipelines / redirects / sequencing (1–4) ───────────

    #[test]
    fn simple_and_quoting_and_sequencing() {
        assert_eq!(
            classify("echo hi there").unwrap(),
            one(&["echo", "hi", "there"])
        );
        assert_eq!(classify("echo 'a b'").unwrap(), one(&["echo", "a b"]));
        assert_eq!(
            classify("a && b").unwrap(),
            vec![
                ScriptItem {
                    sep: Sep::Seq,
                    pipeline: vec![lits(&["a"])]
                },
                ScriptItem {
                    sep: Sep::And,
                    pipeline: vec![lits(&["b"])]
                },
            ]
        );
    }

    // ── globbing (increment 5) ──────────────────────────────────────────────

    #[test]
    fn glob_words_are_marked() {
        assert_eq!(
            classify("ls *.rs").unwrap(),
            vec![ScriptItem {
                sep: Sep::Seq,
                pipeline: vec![stage(vec![lit("ls"), glob("*.rs")])]
            }]
        );
        assert_eq!(
            classify("cat foo?").unwrap(),
            vec![ScriptItem {
                sep: Sep::Seq,
                pipeline: vec![stage(vec![lit("cat"), glob("foo?")])]
            }]
        );
        assert_eq!(
            classify("ls [abc].txt").unwrap(),
            vec![ScriptItem {
                sep: Sep::Seq,
                pipeline: vec![stage(vec![lit("ls"), glob("[abc].txt")])]
            }]
        );
        // Glob in a sub-path keeps the prefix in the pattern.
        assert_eq!(
            classify("cat src/*.rs").unwrap(),
            vec![ScriptItem {
                sep: Sep::Seq,
                pipeline: vec![stage(vec![lit("cat"), glob("src/*.rs")])]
            }]
        );
    }

    /// A quoted metacharacter is a literal arg, NOT a glob.
    #[test]
    fn quoted_glob_chars_are_literal() {
        assert_eq!(classify("echo \"*.rs\"").unwrap(), one(&["echo", "*.rs"]));
        assert_eq!(classify("echo '[abc]'").unwrap(), one(&["echo", "[abc]"]));
        assert_eq!(classify("echo a\\*b").unwrap(), one(&["echo", "a*b"])); // escaped *
    }

    // ── refusals (now $ and fd; globbing is no longer refused) ───────────────

    #[test]
    fn dynamic_unsupported_and_fd_still_refused() {
        assert!(matches!(classify("echo $(id)"), Err(Refusal::Dynamic(_))));
        assert!(matches!(classify("echo `id`"), Err(Refusal::Dynamic(_))));
        assert!(matches!(classify("(echo hi)"), Err(Refusal::Dynamic(_))));
        assert!(matches!(
            classify("echo $HOME"),
            Err(Refusal::Unsupported(_))
        ));
        assert!(matches!(classify("echo 2>f"), Err(Refusal::Unsupported(_))));
        assert!(matches!(classify("echo x &"), Err(Refusal::Unsupported(_))));
    }

    #[test]
    fn empty_and_unterminated_are_malformed() {
        assert!(matches!(classify(""), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("echo 'oops"), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("a &&"), Err(Refusal::Malformed(_))));
    }
}
