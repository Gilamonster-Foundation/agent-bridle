//! A reaped leader with a surviving pipe writer exercises blocking abandonment.

use std::path::Path;
use std::time::{Duration, Instant};

use agent_bridle_core::Tool;

use super::{context, Fixture};

/// The writer's pid as the fixture published it: a nonzero decimal number.
/// Anything else is a failure of the rendezvous, never a process that is gone.
fn parse_pid(text: &str) -> Result<u32, String> {
    let pid = text.trim();
    match pid.parse::<u32>() {
        Ok(0) => Err(format!("pid {pid:?} is not a process")),
        Ok(number) => Ok(number),
        Err(error) => Err(format!("{pid:?} is not a pid: {error}")),
    }
}

/// The state letter of a `/proc/<pid>/stat` read, which must be
/// `<pid> (<name>) <state> ...`: the expected pid, one space, an opening
/// parenthesis, the name, the LAST `)`, one space, one state character from the
/// documented set, then a space. The name can hold spaces and parentheses, so
/// the last `)` closes it. Anything else is an error, never a state.
fn proc_state(pid: u32, stat: &str) -> Result<char, String> {
    let after_name = stat
        .strip_prefix(&format!("{pid} ("))
        .ok_or_else(|| format!("does not start with \"{pid} (\""))?;
    let close = after_name.rfind(')').ok_or("no closing parenthesis")?;
    let rest = after_name[close + 1..]
        .strip_prefix(' ')
        .ok_or("no space after the name")?;
    let mut chars = rest.chars();
    let state = chars.next().ok_or("no state character")?;
    if !"RSDZTtWXxKPI".contains(state) {
        return Err(format!("{state:?} is not a process state"));
    }
    match chars.next() {
        Some(' ') => Ok(state),
        other => Err(format!(
            "state {state:?} is not followed by a space: {other:?}"
        )),
    }
}

/// Whether a failed `/proc/<pid>/stat` read means the process is gone. A missing
/// entry does, and so does ESRCH: the task can be reaped between `open` and
/// `read`, and the kernel then reports "No such process". Any other error says
/// nothing about the process.
fn read_error_means_gone(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(3)
}

/// A reaped or zombie process is gone: a zombie keeps its `/proc` entry until
/// its parent reaps it, but it can no longer run. Only a missing entry (or one
/// reaped mid-read) means reaped; any other unreadable or malformed one is a
/// failure of the check.
fn process_is_gone(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            proc_state(pid, &stat)
                .unwrap_or_else(|why| panic!("pid {pid}: bad stat {stat:?}: {why}"))
                == 'Z'
        }
        Err(error) if read_error_means_gone(&error) => true,
        Err(error) => panic!("cannot read /proc/{pid}/stat: {error}"),
    }
}

/// Controls for the two parsers: no malformed input can mean "gone".
fn liveness_parsers_reject_malformed_input() {
    use std::io::{Error, ErrorKind};
    for gone in [
        Error::from(ErrorKind::NotFound),
        Error::from_raw_os_error(3),
    ] {
        assert!(
            read_error_means_gone(&gone),
            "{gone:?} means the process is gone"
        );
    }
    for unknown in [
        Error::from(ErrorKind::PermissionDenied),
        Error::from_raw_os_error(13),
        Error::from_raw_os_error(5),
    ] {
        assert!(
            !read_error_means_gone(&unknown),
            "{unknown:?} must not mean gone"
        );
    }
    for bad in ["", "   ", "0", "-1", "not-a-pid", "12abc", "4294967296"] {
        assert!(parse_pid(bad).is_err(), "{bad:?} must not parse as a pid");
    }
    assert_eq!(parse_pid(" 4242\n"), Ok(4242));
    for bad in [
        "Z",
        "",
        "123 (hold-pipe)",
        "123 (hold-pipe) ",
        "123 (hold-pipe) Zombie",
        "123 (hold-pipe) Q 1",
        "123 hold-pipe Z 1",
        "123 (hold-pipe)Z 1",
        "123 hold-pipe) Z 1 2",
        ") Z ",
        "456 (hold-pipe) Z 1 2",
        "123 (hold-pipe) z 1 2",
        "123 (hold-pipe) Z",
    ] {
        assert!(
            proc_state(123, bad).is_err(),
            "{bad:?} must not yield a state"
        );
    }
    assert_eq!(proc_state(123, "123 (hold-pipe) S 1 2"), Ok('S'));
    assert_eq!(proc_state(123, "123 (hold-pipe) Z 1 2"), Ok('Z'));
    assert_eq!(proc_state(123, "123 (a b) c) Z 1 2"), Ok('Z'));
    assert_eq!(proc_state(123, "123 (Z) S 1 2"), Ok('S'));
    // The name holds ") Z " itself: the LAST `)` closes it, so the state is R.
    assert_eq!(proc_state(123, "123 (a) Z b) R 1 2"), Ok('R'));
}

/// #2274: dropping the adapter used to join the core reaper on Tokio's sole
/// reactor thread, stalling unrelated timers throughout the pipe-drain grace.
pub(super) fn cancellation_does_not_block_current_thread() {
    liveness_parsers_reject_malformed_input();
    std::thread::spawn(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                let fixture = Fixture::new();
                let arguments = fixture.arguments("orphan-pipe");
                let cx = context(&fixture.caveats());
                let tool = fixture.tool(true);
                let invocation = tokio::spawn(async move { tool.invoke(arguments, &cx).await });
                tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        if let Ok(pid) =
                            std::fs::read_to_string(fixture.workspace.join("exiting-root-pid"))
                        {
                            if !Path::new(&format!("/proc/{pid}")).exists() {
                                break;
                            }
                        }
                        assert!(
                            !invocation.is_finished(),
                            "the live descendant must keep the terminal pending"
                        );
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("leader must be reaped while descendant holds pipe open");
                let before = Instant::now();
                let sibling = tokio::spawn(async {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Instant::now()
                });
                invocation.abort();
                assert!(invocation.await.unwrap_err().is_cancelled());
                let elapsed = sibling.await.unwrap().duration_since(before);
                assert!(
                    elapsed < Duration::from_millis(500),
                    "reactor timer blocked by managed Drop: {elapsed:?}"
                );

                // Abort acknowledgement is not cleanup completion. The supervisor
                // must still finish its bounded drain and tree join, so the
                // surviving writer must die. Poll its liveness against a
                // deadline: a fixed sleep raced the writer's own clock and failed
                // when load delayed the abort (#529).
                // The leader published the writer's pid before the test got here.
                let published = std::fs::read_to_string(fixture.workspace.join("hold-pipe-pid"))
                    .expect("the writer's pid was published before the leader exited");
                let writer = parse_pid(&published)
                    .unwrap_or_else(|why| panic!("the writer published a bad pid: {why}"));
                let deadline = Instant::now() + Duration::from_secs(30);
                while !process_is_gone(writer) {
                    assert!(
                        Instant::now() < deadline,
                        "cleanup must reap the surviving writer (pid {writer})"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                assert!(
                    !fixture.workspace.join("late-marker").exists(),
                    "the surviving writer wrote after cleanup"
                );
            });
    })
    .join()
    .expect("current-thread reactor regression");
}

// Model: gpt-6-astra | Harness: Codex 0.153.4 | Operator: Shawn Hartsock | Time: 22:29 UTC | Date: 2026-09-12
