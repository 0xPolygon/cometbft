package blocksync

import (
	"errors"

	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	bcproto "github.com/cometbft/cometbft/proto/tendermint/blocksync"
)

func (r *Reactor) loadServingResponse(height int64) *bcproto.BlockResponse {
	block := r.store.LoadBlockProto(height)
	if block == nil {
		return &bcproto.BlockResponse{}
	}
	commit, ok := r.loadExtCommit(height)
	if !ok {
		return nil
	}
	return &bcproto.BlockResponse{Block: block, ExtCommit: commit}
}
func (r *Reactor) observeInvalidServing(e p2p.Envelope) {
	reason := servebudget.InvalidResponse
	if _, ok := e.Message.(*bcproto.BlockRequest); ok {
		reason = servebudget.MalformedRequest
	}
	r.Switch.ObserveServing(e.Src, reason)
}

// A delayed response for an already committed block remains an ordinary error.
// Only faults already selected for disconnect carry policy evidence.
type invalidResponseError struct{ error }

func (e invalidResponseError) Unwrap() error { return e.error }

func (pool *BlockPool) rejectResponse(err error, peerID p2p.ID) error {
	fault := invalidResponseError{err}
	pool.sendError(fault, peerID)
	return fault
}

func (r *Reactor) observePeerError(peer p2p.Peer, err error) {
	var fault invalidResponseError
	if errors.As(err, &fault) {
		r.Switch.ObserveServing(peer, servebudget.InvalidResponse)
	}
}
