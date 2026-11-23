//! A reaped leader with a surviving pipe writer exercises blocking abandonment.

use std::path::Path;
use std::time::{Duration, Instant};

use agent_bridle_core::Tool;

use super::{context, Fixture};

/// A reaped or zombie process is gone: a zombie keeps its `/proc` entry until
/// its parent reaps it, but it can no longer run.
fn process_is_gone(pid: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |stat| {
        stat.rsplit(')')
            .next()
            .is_some_and(|rest| rest.trim_start().starts_with('Z'))
    })
}

/// #2274: dropping the adapter used to join the core reaper on Tokio's sole
/// reactor thread, stalling unrelated timers throughout the pipe-drain grace.
pub(super) fn cancellation_does_not_block_current_thread() {
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
                let pid_file = fixture.workspace.join("hold-pipe-pid");
                let deadline = Instant::now() + Duration::from_secs(30);
                let writer = loop {
                    if let Ok(pid) = std::fs::read_to_string(&pid_file) {
                        break pid;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "the writer never published its pid"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                };
                while !process_is_gone(&writer) {
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
