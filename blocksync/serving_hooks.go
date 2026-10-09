package blocksync

import (
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
