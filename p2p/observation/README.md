# Native peer observation hooks

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

This package has no score, admission decision, per-peer map, jail, worker or metric
registration. Heimdall owns bounded policy state and telemetry. Existing disconnects,
blocksync bans, statesync exclusions, rate limits and queue behavior are unchanged.
Asynchronous commit/snapshot validation needs supplier provenance before extending
this correctness interface. Consensus traffic is still delivered unchanged.

Tests exercise real native inbound/outbound transports, decoded traffic,
malformed envelopes, failed queueing, original message types, reactor failures and
neutral local snapshot policy rejection. The interface itself does not promise
nonblocking behavior for an arbitrary application implementation; that is a caller
contract and must be benchmarked and tested by the application.
