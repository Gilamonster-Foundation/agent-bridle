//! Build-tool **delegation** over the worker's surviving private channel.
//!
//! The confused-deputy shape, narrowing only: a sandboxed Brush worker holds no
//! authority to run `cargo`, so instead of *being given* one it **asks** the
//! supervisor to run it. The worker's only new possession is one already
//! connected socket ([`SandboxedWorker::with_delegate_channel`]) — no
//! filesystem root, no `exec` entry, no network. The supervisor computes 100% of
//! the delegated run's fence.
//!
//! [`SandboxedWorker::with_delegate_channel`]: agent_bridle_core::SandboxedWorker::with_delegate_channel
//!
//! Dispatch is by **brush's own name resolution**, not by inspecting shell text:
//! each delegated name is registered as a *builtin*
//! ([`register_build_builtins`]), exactly the mechanism the carried-coreutils
//! shims use. A builtin wins over `PATH`, so `cargo …` reaches the delegate;
//! anything with a path separator (`/usr/bin/cargo`) or behind another program
//! (`env cargo`) is an ordinary external and still meets `before_exec`'s
//! fail-closed denial.
//!
//! Buffered, not streaming (deliberately, agent-bridle has no streaming worker
//! frame): the delegate runs to completion and the whole combined output is
//! written into the builtin's own pipeline stage, so `cargo check | grep` sees
//! the real build's bytes and nothing the worker could substitute afterwards.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use brush_core::builtins::{BoxFuture, ContentOptions, ContentType, Registration};
use brush_core::commands::{CommandArg, ExecutionContext};
use brush_core::extensions::ShellExtensions;
use brush_core::ExecutionExitCode;
use serde::{Deserialize, Serialize};

/// Frame magic — one per direction so a reply can never be read as a request.
const REQUEST_MAGIC: [u8; 4] = *b"ABBQ";
const RESPONSE_MAGIC: [u8; 4] = *b"ABBR";
/// Cap on either direction's JSON body. A build's combined output is truncated
/// to fit rather than growing the supervisor's memory without bound.
const MAX_FRAME: usize = 8 * 1024 * 1024;

/// What the supervisor does on the worker's behalf.
///
/// `argv` and `cwd` are **worker-supplied and therefore untrusted**: an
/// implementation must pin the run inside its own workspace root, compute its
/// own caveats, and supply its own environment. Nothing in this trait carries
/// authority; the implementation is the authority.
pub trait BuildDelegate: Send + Sync + 'static {
    /// Run `argv` for the worker and return `(exit_code, combined_output)`.
    fn run(&self, argv: Vec<String>, cwd: PathBuf) -> (i32, Vec<u8>);
}

#[derive(Debug, Serialize, Deserialize)]
struct Request {
    argv: Vec<String>,
    cwd: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    exit_code: i32,
    output: Vec<u8>,
}

fn write_frame(stream: &mut UnixStream, magic: [u8; 4], body: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| std::io::Error::other("build-delegate frame exceeds its cap"))?;
    stream.write_all(&magic)?;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Read one framed body, or `Ok(None)` at a clean end of stream.
fn read_frame(stream: &mut UnixStream, magic: [u8; 4]) -> std::io::Result<Option<Vec<u8>>> {
    let mut header = [0_u8; 8];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    if header[..4] != magic {
        return Err(std::io::Error::other(
            "build-delegate frame magic mismatch; refusing the frame",
        ));
    }
    let len = u32::from_le_bytes(header[4..8].try_into().expect("4 bytes")) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::other(
            "build-delegate frame exceeds its cap",
        ));
    }
    let mut body = vec![0_u8; len];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

// --------------------------------------------------------------------------
// Supervisor side
// --------------------------------------------------------------------------

/// Serve delegated build requests until the worker closes its end.
///
/// Runs on its own thread for the worker's lifetime. A malformed or
/// over-long frame ends the session — the worker gets no more delegation, and
/// still no authority.
pub(crate) fn serve(mut stream: UnixStream, delegate: &dyn BuildDelegate) {
    loop {
        let body = match read_frame(&mut stream, REQUEST_MAGIC) {
            Ok(Some(body)) => body,
            Ok(None) | Err(_) => return,
        };
        let Ok(request) = serde_json::from_slice::<Request>(&body) else {
            return;
        };
        let (exit_code, mut output) = delegate.run(request.argv, PathBuf::from(request.cwd));
        output.truncate(MAX_FRAME / 2);
        let response = Response { exit_code, output };
        let Ok(body) = serde_json::to_vec(&response) else {
            return;
        };
        if write_frame(&mut stream, RESPONSE_MAGIC, &body).is_err() {
            return;
        }
    }
}

// --------------------------------------------------------------------------
// Worker side
// --------------------------------------------------------------------------

/// The worker's end of the channel. Process-wide because brush's builtin
/// registration takes a plain `fn` pointer, not a closure — the same reason
/// `coreutils_dispatch`'s bundled registry is a `OnceLock`.
static CHANNEL: OnceLock<Mutex<UnixStream>> = OnceLock::new();

/// Install the worker's delegation endpoint. First call wins; a later call is a
/// no-op, so nothing in the worker can replace the supervisor's channel.
pub(crate) fn install_channel(stream: UnixStream) {
    let _ = CHANNEL.set(Mutex::new(stream));
}

/// Ask the supervisor to run `argv` in `cwd`.
fn ask(argv: Vec<String>, cwd: PathBuf) -> Result<Response, String> {
    let channel = CHANNEL
        .get()
        .ok_or_else(|| "no build delegation channel".to_string())?;
    let request = Request {
        argv,
        cwd: cwd.to_string_lossy().into_owned(),
    };
    let body = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    let mut stream = channel
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    write_frame(&mut stream, REQUEST_MAGIC, &body).map_err(|error| error.to_string())?;
    let body = read_frame(&mut stream, RESPONSE_MAGIC)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the build delegate closed its channel".to_string())?;
    serde_json::from_slice(&body).map_err(|error| error.to_string())
}

#[allow(
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    reason = "signature dictated by brush_core::builtins::CommandContentFunc"
)]
fn delegate_content(
    name: &str,
    content_type: ContentType,
    _options: &ContentOptions,
) -> Result<String, brush_core::Error> {
    match content_type {
        ContentType::ShortDescription => Ok(format!("{name} - delegated build tool")),
        ContentType::DetailedHelp => Ok(format!(
            "{name} - run by the supervisor's confined build lane on this shell's behalf\n"
        )),
        ContentType::ShortUsage | ContentType::ManPage => Ok(String::new()),
    }
}

/// The builtin every delegated name shares: ship `{argv, cwd}` to the
/// supervisor, write back what it ran, adopt its exit status.
fn delegate_execute<SE: ShellExtensions>(
    context: ExecutionContext<'_, SE>,
    args: Vec<CommandArg>,
) -> BoxFuture<'_, Result<brush_core::ExecutionResult, brush_core::Error>> {
    Box::pin(async move {
        // The FULL argv the delegate sees, program name included — the
        // supervisor decides what to do with it and never re-resolves a path
        // out of it.
        let mut argv = Vec::with_capacity(args.len());
        argv.push(context.command_name.clone());
        argv.extend(args.into_iter().skip(1).map(|arg| arg.to_string()));
        // The shell's own current directory, as `cd sub` left it. Worker-claimed
        // and therefore re-pinned inside the workspace root by the delegate.
        let cwd = context.shell.working_dir().to_path_buf();

        // Off the shell runtime's thread: a build is minutes long, and a
        // concurrent pipeline stage still needs the reactor polled.
        let asked = tokio::task::spawn_blocking(move || ask(argv, cwd))
            .await
            .map_err(|error| {
                brush_core::Error::from(std::io::Error::other(format!(
                    "join build delegate: {error}"
                )))
            })?;

        match asked {
            Ok(response) => {
                let mut stdout = context.stdout();
                stdout
                    .write_all(&response.output)
                    .and_then(|()| stdout.flush())
                    .map_err(brush_core::Error::from)?;
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "shell exit status is conventionally the low 8 bits"
                )]
                Ok(brush_core::ExecutionResult::new(
                    (response.exit_code & 0xff) as u8,
                ))
            }
            Err(reason) => {
                let _ = writeln!(
                    context.stderr(),
                    "{}: build delegation failed: {reason}",
                    context.command_name
                );
                Ok(ExecutionExitCode::CannotExecute.into())
            }
        }
    })
}

fn delegate_registration<SE: ShellExtensions>() -> Registration<SE> {
    Registration {
        execute_func: delegate_execute::<SE>,
        content_func: delegate_content,
        disabled: false,
        special_builtin: false,
        declaration_builtin: false,
    }
}

/// Register a delegating builtin for each supervisor-named build tool.
///
/// `register_builtin` (not `_if_unset`): the supervisor named these, and a
/// delegated build must not be silently shadowed by a same-named
/// carried-coreutils shim. Nothing is registered when the supervisor named
/// nothing, so a worker without a build grant sees no such command at all and
/// `cargo` resolves through `PATH` to the ordinary fail-closed denial.
pub(crate) fn register_build_builtins<SE: ShellExtensions>(
    shell: &mut brush_core::Shell<SE>,
    names: &[String],
) {
    if CHANNEL.get().is_none() {
        return;
    }
    for name in names {
        shell.register_builtin(name.clone(), delegate_registration::<SE>());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The framing round-trips, and a reply frame is NOT accepted where a
    /// request is expected (the magic is per-direction, so a worker echoing
    /// bytes back cannot be read as a request).
    #[test]
    fn frames_round_trip_and_do_not_cross_directions() {
        let (mut a, mut b) = UnixStream::pair().expect("socketpair");
        write_frame(&mut a, REQUEST_MAGIC, b"hello").expect("write request");
        assert_eq!(
            read_frame(&mut b, REQUEST_MAGIC).expect("read request"),
            Some(b"hello".to_vec())
        );

        write_frame(&mut a, RESPONSE_MAGIC, b"reply").expect("write response");
        assert!(
            read_frame(&mut b, REQUEST_MAGIC).is_err(),
            "a response frame must not be accepted as a request"
        );
    }

    /// A closed peer is a clean end of stream, not an error — that is what ends
    /// the supervisor's serving thread when the worker exits.
    #[test]
    fn a_closed_peer_reads_as_end_of_stream() {
        let (a, mut b) = UnixStream::pair().expect("socketpair");
        drop(a);
        assert_eq!(read_frame(&mut b, REQUEST_MAGIC).expect("clean eof"), None);
    }

    /// The supervisor serves the delegate for every request the worker sends,
    /// and the delegate — not the worker — decides the exit code and bytes.
    #[test]
    fn serve_answers_each_request_from_the_delegate() {
        struct Fixed;
        impl BuildDelegate for Fixed {
            fn run(&self, argv: Vec<String>, cwd: PathBuf) -> (i32, Vec<u8>) {
                (
                    7,
                    format!("ran {:?} in {}", argv, cwd.display()).into_bytes(),
                )
            }
        }

        let (worker, supervisor) = UnixStream::pair().expect("socketpair");
        let serving = std::thread::spawn(move || serve(supervisor, &Fixed));

        let mut worker = worker;
        for _ in 0..2 {
            let body = serde_json::to_vec(&Request {
                argv: vec!["cargo".into(), "check".into()],
                cwd: "/ws/sub".into(),
            })
            .expect("encode");
            write_frame(&mut worker, REQUEST_MAGIC, &body).expect("send request");
            let body = read_frame(&mut worker, RESPONSE_MAGIC)
                .expect("read response")
                .expect("a response");
            let response: Response = serde_json::from_slice(&body).expect("decode");
            assert_eq!(response.exit_code, 7);
            assert_eq!(
                String::from_utf8_lossy(&response.output),
                "ran [\"cargo\", \"check\"] in /ws/sub"
            );
        }
        drop(worker);
        serving.join().expect("serving thread ends at eof");
    }

    /// A frame the supervisor cannot parse ends the session rather than being
    /// guessed at: the worker gets no delegation, and never anything else.
    #[test]
    fn a_garbage_request_ends_the_session() {
        struct Never;
        impl BuildDelegate for Never {
            fn run(&self, _argv: Vec<String>, _cwd: PathBuf) -> (i32, Vec<u8>) {
                panic!("the delegate must not run for an unparseable request");
            }
        }

        let (mut worker, supervisor) = UnixStream::pair().expect("socketpair");
        let serving = std::thread::spawn(move || serve(supervisor, &Never));
        write_frame(&mut worker, REQUEST_MAGIC, b"not json").expect("send garbage");
        serving.join().expect("serving thread ends");
        assert_eq!(
            read_frame(&mut worker, RESPONSE_MAGIC).expect("eof"),
            None,
            "no response frame follows a refused request"
        );
    }
}
