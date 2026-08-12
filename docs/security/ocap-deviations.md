# OCAP Deviation Register

This register records platform-scoped residuals and closures for the v0.8 native
enforcement theorem. A row is closed only when backed by real-resource evidence.

| Area | Platform | State | Evidence / Bound |
| --- | --- | --- | --- |
| descriptor hygiene / inherited HANDLEs (#319) | windows | CLOSED | `handle_inheritance` creates deliberately inheritable file, anonymous-pipe, and WinSock socket canaries in the launcher. The AppContainer child receives stdio through `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` but cannot use the canaries. |
| descriptor hygiene / inherited descriptors (#319) | unix | OPEN | The Windows `HANDLE_LIST` fix does not close Unix descriptor inheritance. A close-range launcher follow-up remains separate. |
| launcher provenance / PATH shadowing | windows | CLOSED | `windows_appcontainer_contract::path_shadowed_aclaunch_refuses_before_fake_launcher_or_target_runs` compiles a fake `agent-bridle-aclaunch.exe`, places it first on `PATH`, and proves the Newt-shaped `CONFINED` route refuses before the fake launcher or hostile target executes. Trusted sources are shipped sibling helper or explicit absolute `SandboxPolicy::appcontainer_launcher_path`. |
| local deputy via named pipe | windows | CLOSED | `local_deputy` creates a NULL-DACL named pipe and host deputy. The unconfined positive control triggers the privileged write; the AppContainer child is denied with `Access is denied.` and the outside marker remains unchanged. |
| remote allowlist proxy | windows | BOUNDED | General remote allowlists remain below Kernel unless routed through the loopback proxy. Native Windows proxy evidence is not promoted above the proxy/over-delivery model. |
| loopback exemption | windows | GATED | Loopback allowance requires elevated `NetworkIsolationSetAppContainerConfig`; CI sets `BRIDLE_REQUIRE_ELEVATED=1`. Non-elevated local runs report the gate instead of counting a skip as proof. |
| UNC-share filesystem escape | windows | ACTIVE | No real UNC-share escape proof has been collected on the non-elevated local host. Junction/reparse, profile, sibling, and normalization variants are covered separately in `fs_adversarial`. |
| hard-kill DACL cleanup | windows | ACTIVE | Normal exit, forced pre-spawn failure, and overlapping same-resource launches revoke scoped AppContainer-SID ACE grants. DACL cleanup after killing the launcher mid-run is not claimed as closed. Timeout/process-tree cleanup remains a separate property from authority containment. |
