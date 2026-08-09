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

On non-Windows platforms the launcher compiles to an explicit unsupported
stub.

Part of [Agent Bridle](https://github.com/Gilamonster-Foundation/agent-bridle).

## License

Apache-2.0
