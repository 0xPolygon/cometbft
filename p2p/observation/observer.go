// Package observation defines optional, in-process peer telemetry hooks.
package observation

import "github.com/cosmos/gogoproto/proto"

// Kind identifies the point at which native protocol processing emitted evidence.
type Kind uint8

const (
	Received Kind = iota
	// Queued means accepted by the local send queue, not delivered or acknowledged.
	Queued
	InvalidEncoding
	InvalidMessage
)

// Event borrows Message for the duration of Observe. Observers must not mutate or
// retain it. Bytes is the existing encoded envelope length, without framing.
type Event struct {
	Kind    Kind
	Channel byte
	Bytes   int
	Message proto.Message
}

// Observer receives telemetry from concurrent networking goroutines. Implementations
// must use bounded work and memory, must not block on I/O or queues, and must not
// call back into networking. Install before startup; never replace while running.
// There is deliberately no admission decision in the observation-only interface.
type Observer interface {
	Observe(peerID string, event Event)
}
