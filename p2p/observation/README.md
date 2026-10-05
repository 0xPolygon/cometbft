# Native peer observation and connection policy hooks

`Observer` is an optional application-owned callback installed through
`Config.P2P.PeerObserver` **before node creation**. The field is ignored by
mapstructure, JSON and TOML; it is not an operator config option. Default nil
preserves the existing networking path. Both inbound and outbound transports
carry the same observer to their peers.

The interface reports:

- `Received`: the decoded, unwrapped message and existing encoded envelope size.
  This precedes reactor validation and is not proof of validity.
- `Queued`: the original unwrapped message and existing encoded envelope size,
  only when Send/TrySend succeeds. This is local queue acceptance, not delivery or
  remote acknowledgement. Failed queues emit nothing.
- `InvalidEncoding`: an existing protobuf decode/unwrap failure, before the
  existing error/disconnect path. No partially decoded message is exposed.
- `InvalidMessage`: an existing blocksync or statesync basic validation failure.
  The configured MaxSnapshotChunks policy rejection is excluded. No extra
  signature, hash, consensus or application validation runs.

Events use the peer ID already authenticated by the native transport. The callback
borrows a protobuf message only until it returns. Implementations must not mutate
or retain it, perform I/O, wait on external queues, call networking recursively or
spawn work per event. The caller may invoke Observe concurrently. Set the observer
once; replacing the interface while networking runs is unsupported.

An optional `ConnectionPolicy` is installed through `Config.P2P.PeerPolicy` before
startup with the same bounded, concurrent, local-call contract. It answers
`AllowPeer(authenticatedNodeID)`. It has no serialized configuration and defaults
to nil. The application owns the score, eligibility and expiry.

The switch checks policy after authentication and before peer/reactor admission in
both directions. A peer checks it before sending and after transport observations.
Denied received messages do not reach their reactor. Denial closes the connection
once and uses the existing connection-error/removal path. A successful local enqueue
still returns success even if its observation then causes disconnection; it is not
a promise of delivery. Existing reactor invalidity reports still use their native
disconnect path, after updating evidence.

Persistent and unconditional peers also pass the policy gate. Persistent redial
and backoff remain native; a policy rejection is non-terminal for redial. Admission
can reopen when application evidence expires. Checks do not themselves create
misconduct evidence, and this package adds no score ledger, jail timer or worker.
Existing blocksync bans, statesync exclusions and rate limits retain their own
semantics and may independently exclude a peer.

This is a connection gate, not a pre-decode or pre-storage serving budget. It cannot
recover bandwidth or work already consumed. Asynchronous commit/snapshot validation
still needs supplier provenance before extending correctness evidence. Consensus
validation is unchanged; disconnecting a peer stops all its channels.

Tests exercise real native inbound/outbound transports, decoded traffic,
malformed envelopes, failed queueing, original message types, reactor failures and
neutral local snapshot policy rejection, admission in both directions, active-peer
removal, policy expiry and persistent-peer send gating. The interface itself does not promise
nonblocking behavior for an arbitrary application implementation; that is a caller
contract and must be benchmarked and tested by the application.
