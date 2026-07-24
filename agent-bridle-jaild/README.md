# agent-bridle-jaild

`agent-bridle-jaild` is Agent Bridle's privileged Linux confinement service.
It derives a minimal root filesystem from capability caveats, enforces program
identity, and runs the requested process inside a mount namespace after
dropping to the requesting user's identity. The crate also contains the
minimal-rootfs micro-VM support and guest init used by the stronger isolation
tier.

This deployment-specific component requires host packaging and privileged
setup; it is intentionally not published as a standalone crates.io package.
Its broker protocol accepts authority caveats rather than trusting a
client-supplied filesystem plan.

Part of [Agent Bridle](https://github.com/Gilamonster-Foundation/agent-bridle).

## License

Apache-2.0
