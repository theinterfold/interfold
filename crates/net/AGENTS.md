# e3-net

This is transport/admission and delivery infrastructure, not committee authorization. QUIC or a
signed gossip envelope authenticates a peer, not that peer's right to fill an E3 dealer slot.

- Keep network/deployment/aggregate/wire admission before translation and domain dispatch. Peer
  history never imports local aggregate zero; public profiles cannot infer unrestricted policy.
- Do not block ingress on DHT reads. Preserve propagation-peer attribution through transient queues,
  but keep transport attribution out of document identity and persisted protocol payloads.
- Connected peers are not necessarily gossip-ready. Preserve topic-health repair and filtered
  Identify/Kademlia addresses instead of adding an independent address cache.
- DHT acknowledgment is not durable replication. Preserve document/hash/metadata checks, fair
  bounded fetches, and terminal cleanup; cancellation of already-handed-off requests is incomplete.
- Command results go directly to their registered caller before broadcast; do not accidentally fence
  them behind startup application buffering. Publications themselves wait for SyncEnded.

[Network delivery](../../docs/architecture/network-delivery.md) owns budgets and loss windows. Run
`cargo test -p e3-net`; a peer restart test must assert topic readiness, not connection count alone.
