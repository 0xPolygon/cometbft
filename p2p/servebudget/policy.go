// Package servebudget defines bounded, in-process hooks owned by the embedding application.
package servebudget

type Family uint8

const (
	Block Family = iota
	Snapshot
	Chunk
	Catchup
)

type Request struct {
	Family        Family
	Height        uint64
	Format, Index uint32
	// MaxBytes bounds the response payload retained during loading and transport.
	MaxBytes uint64
}

type Evidence uint8

const (
	MalformedRequest Evidence = iota
	InvalidResponse
)

// Policy implementations must be concurrency safe and perform only bounded local
// work. They must not call networking methods, perform I/O, or wait for capacity.
type Policy interface {
	Admit(peerID string, request Request) (Lease, bool)
	Observe(peerID string, evidence Evidence)
}

// Lease spans the store read through transport completion. Prepare reserves actual
// encoded bytes before queueing. Finish is idempotent; true means a local flush,
// never remote receipt. Failed work retains its work charge.
type Lease interface {
	Prepare(bytes uint64) bool
	Finish(written bool)
}
