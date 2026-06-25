//! Safe-subset command-line parsing for the confined shell engine (ADR 0005 D3).
//!
//! `agent-bridle` is the **exec funnel**: rather than hand a string to a shell
//! interpreter, the engine parses it itself and runs only what it can confine.
//! This covers **increments 1–6** — a sequence of pipelines joined by `&&`,
//! `||` and `;`, each pipeline simple commands (`a | b | c`) with quoted
//! arguments, file redirections (`> out`, `>> out`, `< in`), filename globbing
//! (`*`, `?`, `[…]`), and **whole-word variable expansion** (`$VAR` / `${VAR}`).
//! The parser only *marks* an argument ([`Arg::Glob`] / [`Arg::Var`]); the
//! filesystem read (globbing) and the env read + allowlist check (variables) are
//! the executor's job.
//!
//! Refused **by design** (security, [`Refusal::Dynamic`]): command/arithmetic
//! substitution `$(…)`, backticks, subshells — the undecidable interiors ADR
//! 0001 says may never be statically cleared. Refused for now
//! ([`Refusal::Unsupported`]): `$VAR` mixed into a larger word (use a standalone
//! `$VAR`), `$VAR` inside double quotes, fd-number redirections (`2>`, `2>&1`).
//!
//! Quoting is honored, so a metacharacter **inside quotes is a literal
//! argument** — only *unquoted* operators and constructs are recognized:
//! `echo "a*b"` is one literal arg, `echo a*` is a glob, `echo $HOME` is a
//! variable, and `a && b` is two pipelines joined by `&&`.

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
    /// this increment (mixed/quoted variable expansion, fd-number redirections).
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

/// One argument word: a literal, a glob pattern, or a variable reference. The
/// executor lowers globs (a filesystem read) and variables (an env read +
/// allowlist check) into literals — both leash-/policy-checked first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// A literal word (quoting already resolved).
    Lit(String),
    /// A word containing unquoted `*`/`?`/`[…]` — a glob pattern.
    Glob(String),
    /// A standalone `$NAME` / `${NAME}` variable reference (the name only).
    Var(String),
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

/// One command stage: its argv (literals/globs/variables) plus any redirections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The program (argv[0]) and arguments.
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
            // Words (literals, globs, `$VAR`) are read by `read_word`.
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

/// Read the next word as an [`Arg`]. Stops at unquoted whitespace or an operator.
/// Single quotes are literal; double quotes are literal except `$`/backtick still
/// trigger substitution detection; an unquoted backslash escapes the next char.
/// An unquoted `*`/`?`/`[` marks the word a glob; an unquoted `$` at the start of
/// a word begins a standalone variable reference (see [`read_variable`]).
fn read_word(chars: &mut Peekable<Chars>) -> Result<Arg, Refusal> {
    let mut cur = String::new();
    let mut is_glob = false;
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => break,
            '|' | '&' | ';' | '<' | '>' | '(' | ')' | '`' => break,
            '$' => {
                // A variable is only allowed as a *standalone* word.
                if !cur.is_empty() || is_glob {
                    return Err(Refusal::Unsupported(
                        "mixed variable expansion (use a standalone $VAR)",
                    ));
                }
                chars.next(); // consume '$'
                return read_variable(chars);
            }
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
                        // `$VAR` inside double quotes is not expanded here — use a
                        // bare `$VAR`. (Avoids the segment model; a documented gap.)
                        Some('$') => {
                            return Err(Refusal::Unsupported(
                                "variable expansion inside double quotes (use a bare $VAR)",
                            ))
                        }
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
    Ok(if is_glob {
        Arg::Glob(cur)
    } else {
        Arg::Lit(cur)
    })
}

/// Read a variable reference after a consumed `$`: `$NAME` or `${NAME}`. The
/// variable must be a **whole word** (nothing else adjacent). `$(` is dynamic.
fn read_variable(chars: &mut Peekable<Chars>) -> Result<Arg, Refusal> {
    let name = match chars.peek() {
        Some('(') => return Err(Refusal::Dynamic("command/arithmetic substitution `$(`")),
        Some('{') => {
            chars.next(); // consume '{'
            let mut name = String::new();
            loop {
                match chars.next() {
                    Some('}') => break,
                    Some(ch) => name.push(ch),
                    None => return Err(Refusal::Malformed("unterminated `${`".into())),
                }
            }
            name
        }
        Some(&c) if c == '_' || c.is_ascii_alphabetic() => {
            let mut name = String::new();
            while let Some(&ch) = chars.peek() {
                if ch == '_' || ch.is_ascii_alphanumeric() {
                    name.push(ch);
                    chars.next();
                } else {
                    break;
                }
            }
            name
        }
        _ => {
            return Err(Refusal::Unsupported(
                "bare `$` (escape as `\\$` for a literal dollar)",
            ))
        }
    };
    if !is_valid_var_name(&name) {
        return Err(Refusal::Unsupported("unsupported variable name"));
    }
    // Whole-word only: the variable must be the entire word.
    match chars.peek() {
        None => {}
        Some(&(' ' | '\t' | '\n' | '\r' | '|' | '&' | ';' | '<' | '>' | '(' | ')')) => {}
        _ => {
            return Err(Refusal::Unsupported(
                "mixed variable expansion (use a standalone $VAR)",
            ))
        }
    }
    Ok(Arg::Var(name))
}

/// A valid environment variable name: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Read a redirection target (the word after `>`/`>>`/`<`). The target must be a
/// plain literal — globs and variables in a redirect target are refused.
fn read_redirect_target(chars: &mut Peekable<Chars>) -> Result<String, Refusal> {
    skip_whitespace(chars);
    match chars.peek().copied() {
        None | Some('|' | '&' | ';' | '<' | '>' | '(' | ')') => {
            return Err(Refusal::Malformed("missing redirection target".into()))
        }
        _ => {}
    }
    match read_word(chars)? {
        Arg::Lit(s) if !s.is_empty() => Ok(s),
        Arg::Lit(_) => Err(Refusal::Malformed("empty redirection target".into())),
        Arg::Glob(_) => Err(Refusal::Unsupported("glob in a redirection target")),
        Arg::Var(_) => Err(Refusal::Unsupported("variable in a redirection target")),
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
    fn var(s: &str) -> Arg {
        Arg::Var(s.to_string())
    }
    fn stage(args: Vec<Arg>) -> Command {
        Command {
            argv: args,
            redirects: vec![],
        }
    }
    fn one_stage(args: Vec<Arg>) -> Script {
        vec![ScriptItem {
            sep: Sep::Seq,
            pipeline: vec![stage(args)],
        }]
    }

    // ── carried behavior (1–5) ──────────────────────────────────────────────

    #[test]
    fn literals_globs_pipelines_redirects_sequencing() {
        assert_eq!(
            classify("echo hi").unwrap(),
            one_stage(vec![lit("echo"), lit("hi")])
        );
        assert_eq!(
            classify("ls *.rs").unwrap(),
            one_stage(vec![lit("ls"), glob("*.rs")])
        );
        assert_eq!(
            classify("echo \"a*b\"").unwrap(),
            one_stage(vec![lit("echo"), lit("a*b")])
        );
        assert!(classify("a && b").is_ok());
        let p = classify("echo hi > out").unwrap();
        assert_eq!(p[0].pipeline[0].stdout_redirect(), Some(("out", false)));
    }

    // ── variable expansion (increment 6) ────────────────────────────────────

    #[test]
    fn standalone_variables_are_marked() {
        assert_eq!(
            classify("echo $HOME").unwrap(),
            one_stage(vec![lit("echo"), var("HOME")])
        );
        assert_eq!(
            classify("echo ${HOME}").unwrap(),
            one_stage(vec![lit("echo"), var("HOME")])
        );
        assert_eq!(
            classify("ls $TMPDIR").unwrap(),
            one_stage(vec![lit("ls"), var("TMPDIR")])
        );
        // A variable followed by an operator is still a whole word (here `|`,
        // so this is a single pipeline with two stages).
        assert_eq!(
            classify("cat $FILE | wc").unwrap(),
            vec![ScriptItem {
                sep: Sep::Seq,
                pipeline: vec![stage(vec![lit("cat"), var("FILE")]), stage(vec![lit("wc")])],
            }]
        );
    }

    #[test]
    fn mixed_or_quoted_or_invalid_variables_are_refused() {
        assert!(matches!(
            classify("echo $HOME/x"),
            Err(Refusal::Unsupported(_))
        )); // mixed
        assert!(matches!(
            classify("echo foo$HOME"),
            Err(Refusal::Unsupported(_))
        )); // mixed
        assert!(matches!(
            classify("echo \"$HOME\""),
            Err(Refusal::Unsupported(_))
        )); // quoted
        assert!(matches!(classify("echo $1"), Err(Refusal::Unsupported(_)))); // positional/invalid
        assert!(matches!(classify("echo $"), Err(Refusal::Unsupported(_)))); // bare $
        assert!(matches!(classify("echo $(id)"), Err(Refusal::Dynamic(_)))); // substitution
                                                                             // Escaped `$` is a literal dollar, not a variable.
        assert_eq!(
            classify("echo \\$HOME").unwrap(),
            one_stage(vec![lit("echo"), lit("$HOME")])
        );
    }

    #[test]
    fn variables_refused_in_redirect_targets() {
        assert!(matches!(
            classify("echo hi > $HOME"),
            Err(Refusal::Unsupported(_))
        ));
    }

    // ── other refusals still hold ───────────────────────────────────────────

    #[test]
    fn dynamic_and_fd_and_malformed_still_refused() {
        assert!(matches!(classify("echo `id`"), Err(Refusal::Dynamic(_))));
        assert!(matches!(classify("(echo hi)"), Err(Refusal::Dynamic(_))));
        assert!(matches!(classify("echo 2>f"), Err(Refusal::Unsupported(_))));
        assert!(matches!(classify(""), Err(Refusal::Malformed(_))));
        assert!(matches!(classify("a &&"), Err(Refusal::Malformed(_))));
    }
}
