# agent-bridle-aclaunch

`agent-bridle-aclaunch` is Agent Bridle's Windows AppContainer launcher. It
creates a fresh AppContainer process, preserves the child's standard streams,
waits for it to finish, and returns the child's exit status.

This is an internal companion binary, not a separately supported crates.io
surface. The Windows `agent-bridle-mcp` release archive bundles it so the
`windows-appcontainer` backend can apply kernel confinement at process
creation. Strong AppContainer requests trust this helper only when it is shipped
next to the current executable, or when the host supplies an explicit absolute
`SandboxPolicy::appcontainer_launcher_path`; ambient `PATH` is not a launcher
provenance source.

The launcher delegates stdio through `STARTUPINFOEXW` with an explicit
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`; arbitrary inheritable launcher handles are
not ambiently inherited by the confined child. The additional `ab-netprobe`,
`ab-handleprobe`, and `ab-fsprobe` binaries are test fixtures for network,
inherited-handle, and filesystem ACL concurrency proofs.

## Direct-caller warning: `--nul-device-ace`

`--nul-device-ace` is an explicit, default-off compatibility widening for native
Git on Windows Server AppContainer policies that deny its startup open of `NUL`.
It is not a regular filesystem grant. When requested, the launcher adds one
`FILE_GENERIC_READ | FILE_GENERIC_WRITE` ACE for this launch's fresh AppContainer
SID to the host `\\.\NUL` device DACL, and removes exactly that SID's ACE on
ordinary cleanup. It requires `WRITE_DAC` (normally elevation); failure to obtain
that right refuses the launch rather than running without the requested grant.
Without `--nul-device-ace`, the launcher neither opens nor modifies `\\.\NUL`.
The option requires a fresh profile/SID. An existing profile already fails the
launcher's baseline because `CreateAppContainerProfile` returns no usable SID;
the opt-in does not add a separate profile-reuse store or cleanup mechanism.

Concurrent launches are safe only because cleanup is SID-specific: callers must
never snapshot and restore the whole device DACL. A launcher crash or failed
revocation can leave residual host state. A crash leaves the profile undeleted;
an exact-ACE revocation failure deliberately leaves it undeleted. In either case,
a later launcher invocation cannot obtain a fresh SID for that existing name.
External profile deletion is outside this lifecycle and does not resolve residual
host authority. See `SECURITY.md`, ADR 0009 amendment D6.1, and
[agent-bridle #408](https://github.com/Gilamonster-Foundation/agent-bridle/issues/408).

On non-Windows platforms the launcher compiles to an explicit unsupported
stub.

Part of [Agent Bridle](https://github.com/Gilamonster-Foundation/agent-bridle).

## License

Apache-2.0
