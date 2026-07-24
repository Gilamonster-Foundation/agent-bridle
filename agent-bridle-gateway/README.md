# agent-bridle-gateway

`agent-bridle-gateway` is the local browser-to-agent presence gateway and
operator console for Agent Bridle. It serves its HTTP and WebSocket interface
on loopback and reuses the authority and step-up types from
`agent-bridle-core`.

The current gateway is an unpublished MVP with a mocked agent-mesh transport.
It demonstrates enrollment, presence challenges, discharge flow, and traffic
history without claiming that the mocked leg performs production credential
verification.

Part of [Agent Bridle](https://github.com/Gilamonster-Foundation/agent-bridle).

## License

Apache-2.0
