# Windows AppContainer Evidence

Evidence collected on:

- Host: Microsoft Windows NT 10.0.26200.0, x86_64
- Rust: rustc 1.93.1 (x86_64-pc-windows-msvc)
- Branch: `fix/windows-v080-ocap-closure`, stacked on PR #317 head `6dab4b4`
- Token elevation: not elevated; loopback-exemption proof is CI/elevated-runner only on this host

## v0.8 Rows

| Row | Result | Evidence |
| --- | --- | --- |
| inherited HANDLEs | DENIED | `BRIDLE_REQUIRE_APPCONTAINER=1 cargo test -p agent-bridle-aclaunch --test handle_inheritance -- --test-threads=1 --nocapture` passed. Before the fix, the outside-file canary wrote `LEAKED_FILE_HANDLE` through an intentionally inheritable HANDLE held by the launcher. After the fix, the same canary file remained unchanged and both file and anonymous-pipe canaries were nondelegated. Observed denial signatures were `HANDLE_WRITE_DENIED` or exact `STATUS_INVALID_HANDLE`, not command-not-found or a missing resource. |
| fs_read | BOUNDED | Existing native suite passed with `BRIDLE_REQUIRE_APPCONTAINER=1 cargo test -p agent-bridle-aclaunch --test kernel_proofs -- --test-threads=1`. `BRIDLE_REQUIRE_APPCONTAINER=1 cargo test -p agent-bridle-aclaunch --test fs_adversarial -- --test-threads=1 --nocapture` passed for junction read escape denial and DACL restoration after normal/forced-failure exits. UNC-share evidence and hard-kill cleanup remain unproven on this non-elevated host, so the row is bounded rather than fully closed. |
| fs_write | BOUNDED | Existing native suite passed with `BRIDLE_REQUIRE_APPCONTAINER=1 cargo test -p agent-bridle-aclaunch --test kernel_proofs -- --test-threads=1`. `fs_adversarial` passed for junction write escape denial and two concurrent children with disjoint workspace grants. UNC-share evidence and hard-kill cleanup remain unproven on this non-elevated host, so the row is bounded rather than fully closed. |
| net:none | DENIED | `cargo test -p agent-bridle-aclaunch --test net_proofs -- --test-threads=1 --nocapture` passed for TCP IPv4 loopback denial and UDP IPv4/IPv6 loopback non-delivery to live positive-control listeners. UDP denial is a no-delivery result: the child `send_to` may return success, but the datagram does not reach the listener that receives the unconfined positive control. Manual off-box TCP evidence on this host: unconfined `ab-netprobe tcp 1.1.1.1 443` exited `0`; the same staged probe through `agent-bridle-aclaunch --fs-read <probe-dir> ... tcp 1.1.1.1 443` exited `1` with Winsock `10013` (`access permissions`). A DNS-name control to `example.com:80` also showed parent success and confined name-resolution denial, but the IP result is the primary direct off-box evidence. |
| loopback | GATED | `net_loopback_exemption_permits_loopback` is gated on an elevated token because `NetworkIsolationSetAppContainerConfig` requires it. This local host was not elevated, so the local run returned early and is not counted as proof. |
| remote allowlist/proxy | BOUNDED | PR #317 policy keeps general remote allowlists below Kernel unless routed through the loopback proxy. Native Windows proxy evidence remains to be filled. |
| exec deny-all | DENIED | Existing native suite passed with `BRIDLE_REQUIRE_APPCONTAINER=1 cargo test -p agent-bridle-aclaunch --test kernel_proofs -- --test-threads=1`; `--no-child-process` blocked the `cmd.exe` grandchild marker write. |
| exec allowlist | GATED | PR #317 reports non-empty Windows exec allowlists as `Interceptor`, not `Kernel`. Native route-level evidence remains to be filled. |
| descendants | BOUNDED | `BRIDLE_REQUIRE_APPCONTAINER=1 cargo test -p agent-bridle-aclaunch --test descendants -- --test-threads=1 --nocapture` passed. Direct helper child reported `TokenIsAppContainer=1` and `S-1-15-2-*` AppContainer SID. `cmd.exe`, PowerShell, and helper-spawned `cmd.exe` descendants reported the low-integrity token boundary (`S-1-16-4096`). A staged arbitrary helper executable could run as the initial child but was denied when a container descendant tried to execute it, so this route is bounded rather than promoted to a universal arbitrary-helper grandchild theorem. |
| named-pipe deputy | DENIED | `BRIDLE_REQUIRE_APPCONTAINER=1 cargo test -p agent-bridle-aclaunch --test local_deputy -- --test-threads=1 --nocapture` passed. The test creates a deliberately permissive NULL-DACL named pipe and a host deputy that writes an outside-authority marker when it receives `WRITE_OUTSIDE`. The unconfined positive-control client reached the pipe and triggered `DEPUTY_WROTE`; the AppContainer child using the same `cmd.exe` redirection route failed with `Access is denied.`, the server only received the parent fallback `NOOP`, and the outside marker remained `ORIG`. |
| missing backend | UNSUPPORTED_FAIL_CLOSED | `BRIDLE_REQUIRE_APPCONTAINER=1 cargo test -p agent-bridle-aclaunch --test fail_closed -- --test-threads=1 --nocapture` passed for profile creation failure, required ACL grant failure, and forced process-attribute failure. Each case asserted the hostile stdout marker was absent before classifying refusal. `cargo test -p agent-bridle-core --features windows-appcontainer appcontainer_impl::tests -- --nocapture` passed for missing `agent-bridle-aclaunch.exe` mapping to `ToolError::Denied` before any launcher prefix can be used. |

## Notes

- The inherited-HANDLE result is a Windows process-creation property, not an AppContainer DACL denial. The confined child receives stdio handles via an explicit handle list and does not receive other inheritable launcher handles.
- A Windows SOCKET canary is not recorded here yet. WinSock `SOCKET` inheritance has a different API surface from kernel HANDLE inheritance and will be evaluated with the expanded network suite instead of being folded into the #319 HANDLE row.
