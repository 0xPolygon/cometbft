package statesync

import (
	"context"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	ssproto "github.com/cometbft/cometbft/proto/tendermint/statesync"
)

func (r *Reactor) serveChunk(e p2p.Envelope, msg *ssproto.ChunkRequest) {
	r.Logger.Debug("Serving snapshot chunk", "peer", e.Src.ID(), "height", msg.Height, "index", msg.Index)
	lease, ok := r.Switch.AdmitServing(e.Src, servebudget.Request{Family: servebudget.Chunk, Height: msg.Height, Format: msg.Format, Index: msg.Index, MaxBytes: uint64(chunkMsgSize)})
	if !ok {
		return
	}
	defer func() { p2p.FinishServing(lease) }()
	resp, err := r.conn.LoadSnapshotChunk(context.TODO(), &abci.RequestLoadSnapshotChunk{Height: msg.Height, Format: msg.Format, Chunk: msg.Index})
	if err != nil {
		r.Logger.Error("Failed to load chunk", "err", err)
		return
	}
	response := p2p.Envelope{ChannelID: ChunkChannel, Message: &ssproto.ChunkResponse{Height: msg.Height, Format: msg.Format, Index: msg.Index, Chunk: resp.Chunk, Missing: resp.Chunk == nil}}
	if resp.Chunk == nil {
		e.Src.TrySend(response)
		return
	}
	p2p.SendServing(e.Src, lease, response)
	lease = nil
}

func (r *Reactor) serveSnapshots(e p2p.Envelope) {
	lease, ok := r.Switch.AdmitServing(e.Src, servebudget.Request{Family: servebudget.Snapshot, MaxBytes: uint64(recentSnapshots * snapshotMsgSize)})
	if !ok {
		return
	}
	defer func() { p2p.FinishServing(lease) }()
	snapshots, err := r.recentSnapshots(recentSnapshots)
	if err != nil {
		r.Logger.Error("Failed to fetch snapshots", "err", err)
		return
	}
	responses := make([]p2p.Envelope, 0, len(snapshots))
	for _, snapshot := range snapshots {
		r.Logger.Debug("Serving snapshot descriptor", "peer", e.Src.ID(), "height", snapshot.Height)
		responses = append(responses, p2p.Envelope{ChannelID: e.ChannelID, Message: &ssproto.SnapshotsResponse{Height: snapshot.Height, Format: snapshot.Format, Chunks: snapshot.Chunks, Hash: snapshot.Hash, Metadata: snapshot.Metadata}})
	}
	p2p.SendServing(e.Src, lease, responses...)
	lease = nil
}
