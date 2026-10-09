package consensus

import (
	"time"

	cstypes "github.com/cometbft/cometbft/consensus/types"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	cmtcons "github.com/cometbft/cometbft/proto/tendermint/consensus"
	"github.com/cometbft/cometbft/types"
)

func (r *Reactor) loadCatchupMeta(peer p2p.Peer, height int64) *types.BlockMeta {
	lease, ok := r.Switch.AdmitServing(peer, servebudget.Request{Family: servebudget.Catchup, Height: uint64(height), MaxBytes: 4096})
	if !ok {
		return nil
	}
	defer p2p.FinishServing(lease)
	return r.conS.blockStore.LoadBlockMeta(height)
}

func (r *Reactor) loadCatchupCommit(height int64) types.VoteSetReader {
	r.conS.mtx.RLock()
	enabled := r.conS.state.ConsensusParams.ABCI.VoteExtensionsEnabled(height)
	r.conS.mtx.RUnlock()
	if enabled {
		ec := r.conS.blockStore.LoadBlockExtendedCommit(height)
		if ec == nil {
			return nil
		}
		return ec
	}
	c := r.conS.blockStore.LoadBlockCommit(height)
	if c == nil {
		return nil
	}
	return c.WrappedExtendedCommit()
}

func (r *Reactor) sendCatchupVote(peer p2p.Peer, ps *PeerState, height int64, load func() types.VoteSetReader) bool {
	lease, ok := r.Switch.AdmitServing(peer, servebudget.Request{Family: servebudget.Catchup, Height: uint64(height), Format: 1, MaxBytes: uint64(types.MaxBlockSizeBytes)})
	if !ok {
		return false
	}
	defer func() { p2p.FinishServing(lease) }()
	votes := load()
	if votes == nil {
		return false
	}
	vote, ok := ps.PickVoteToSend(votes)
	if !ok {
		return false
	}
	sent := p2p.SendServing(peer, lease, p2p.Envelope{ChannelID: VoteChannel, Message: &cmtcons.Vote{Vote: vote.ToProto()}})
	lease = nil
	if sent {
		ps.SetHasVote(vote)
	}
	return sent
}

func (r *Reactor) loadCatchupMajority(peer p2p.Peer, height int64) *types.Commit {
	lease, ok := r.Switch.AdmitServing(peer, servebudget.Request{Family: servebudget.Catchup, Height: uint64(height), Format: 2, MaxBytes: uint64(types.MaxBlockSizeBytes)})
	if !ok {
		return nil
	}
	defer p2p.FinishServing(lease)
	return r.conS.LoadCommit(height)
}

func (conR *Reactor) loadCatchupPart(logger log.Logger, rs *cstypes.RoundState, prs *cstypes.PeerRoundState, index int) *types.Part {
	// Ensure that the peer's PartSetHeader is correct
	blockMeta := conR.conS.blockStore.LoadBlockMeta(prs.Height)
	if blockMeta == nil {
		logger.Error("Failed to load block meta", "ourHeight", rs.Height,
			"blockstoreBase", conR.conS.blockStore.Base(), "blockstoreHeight", conR.conS.blockStore.Height())
		time.Sleep(conR.conS.config.PeerGossipSleepDuration)
		return nil
	} else if !blockMeta.BlockID.PartSetHeader.Equals(prs.ProposalBlockPartSetHeader) {
		logger.Info("Peer ProposalBlockPartSetHeader mismatch, sleeping",
			"blockPartSetHeader", blockMeta.BlockID.PartSetHeader, "peerBlockPartSetHeader", prs.ProposalBlockPartSetHeader)
		time.Sleep(conR.conS.config.PeerGossipSleepDuration)
		return nil
	}
	// Load the part
	part := conR.conS.blockStore.LoadBlockPart(prs.Height, index)
	if part == nil {
		logger.Error("Could not load part", "index", index,
			"blockPartSetHeader", blockMeta.BlockID.PartSetHeader, "peerBlockPartSetHeader", prs.ProposalBlockPartSetHeader)
		time.Sleep(conR.conS.config.PeerGossipSleepDuration)
		return nil
	}
	return part
}
