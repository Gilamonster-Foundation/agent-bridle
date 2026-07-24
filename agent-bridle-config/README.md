# agent-bridle-config

`agent-bridle-config` is Agent Bridle's layered configuration loader. It
combines built-in defaults, a TOML file, environment variables, and a
programmatic overlay in that precedence order, deep-merging individual fields
without replacing unrelated settings.

Configuration data types remain in `agent-bridle-core`; this internal crate
owns file, environment, and TOML loading so those dependencies do not enter
the lean enforcement core. It is not a separately supported crates.io
surface.

Part of [Agent Bridle](https://github.com/Gilamonster-Foundation/agent-bridle).

## License

Apache-2.0
