# agent-bridle-aclaunch

`agent-bridle-aclaunch` is Agent Bridle's Windows AppContainer launcher. It
creates a fresh AppContainer process, preserves the child's standard streams,
waits for it to finish, and returns the child's exit status.

This is an internal companion binary, not a separately supported crates.io
surface. The Windows `agent-bridle-mcp` release archive bundles it so the
`windows-appcontainer` backend can apply kernel confinement at process
creation.

The launcher delegates stdio through `STARTUPINFOEXW` with an explicit
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`; arbitrary inheritable launcher handles are
not ambiently inherited by the confined child. The additional `ab-netprobe` and
`ab-handleprobe` binaries are test fixtures for network and inherited-handle
confinement proofs.

On non-Windows platforms the launcher compiles to an explicit unsupported
stub.

Part of [Agent Bridle](https://github.com/Gilamonster-Foundation/agent-bridle).

## License

Apache-2.0
