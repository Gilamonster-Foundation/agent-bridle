# agent-bridle-ceremony

`agent-bridle-ceremony` is Agent Bridle's dependency-free authority kernel. It
implements the `Effect × Assurance × Scope` product meet-lattice, attenuation,
signed-object verification order, and append-only chain-store state machine
that mirror the repository's Lean and TLA+ models.

The crate is deliberately unpublished while the Ceremony Suite wire profiles
and conformance vectors remain under development. It contains pure,
panic-free policy algebra and no serialization or operating-system effects.

Part of [Agent Bridle](https://github.com/Gilamonster-Foundation/agent-bridle).

## License

Apache-2.0
