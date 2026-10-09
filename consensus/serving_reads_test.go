package consensus

import (
	"testing"

	cstypes "github.com/cometbft/cometbft/consensus/types"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/state/mocks"
	"github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

func TestNativeServingCommitRead(t *testing.T) {
	for _, extensions := range []bool{false, true} {
		for _, present := range []bool{false, true} {
			t.Run(map[bool]string{false: "plain", true: "extended"}[extensions]+map[bool]string{false: "_missing", true: "_present"}[present], func(t *testing.T) {
				store := &mocks.BlockStore{}
				r := servingReactor(nil, store)
				if extensions {
					r.conS.state.ConsensusParams.ABCI.VoteExtensionsEnableHeight = 1
				}
				if extensions {
					var commit *types.ExtendedCommit
					if present {
						commit = &types.ExtendedCommit{Height: 1}
					}
					store.On("LoadBlockExtendedCommit", int64(1)).Return(commit).Once()
				} else {
					var commit *types.Commit
					if present {
						commit = &types.Commit{Height: 1}
					}
					store.On("LoadBlockCommit", int64(1)).Return(commit).Once()
				}
				got := r.loadCatchupCommit(1)
				if present {
					require.NotNil(t, got)
					require.Equal(t, int64(1), got.GetHeight())
				} else {
					require.Nil(t, got)
				}
				store.AssertExpectations(t)
			})
		}
	}
}

func TestNativeServingMetaRead(t *testing.T) {
	lease := &servingLease{}
	policy := &acceptedPolicy{lease: lease}
	store := &mocks.BlockStore{}
	meta := &types.BlockMeta{Header: types.Header{Height: 1}}
	store.On("LoadBlockMeta", int64(1)).Return(meta).Once()
	r := servingReactor(policy, store)
	require.Same(t, meta, r.loadCatchupMeta(servingPeer{}, 1))
	require.Equal(t, []bool{false}, lease.results)
	require.Len(t, policy.requests, 1)
	store.AssertExpectations(t)
}

func TestNativeServingMissingPart(t *testing.T) {
	for _, reason := range []string{"metadata", "header", "part"} {
		t.Run(reason, func(t *testing.T) {
			store := &mocks.BlockStore{}
			parts := types.NewPartSetFromData([]byte("block"), types.PartSizeBytes)
			var meta *types.BlockMeta
			if reason != "metadata" {
				meta = &types.BlockMeta{BlockID: types.BlockID{PartSetHeader: parts.Header()}}
			}
			store.On("LoadBlockMeta", int64(1)).Return(meta).Once()
			prs := &cstypes.PeerRoundState{Height: 1}
			if reason == "part" {
				prs.ProposalBlockPartSetHeader = parts.Header()
				store.On("LoadBlockPart", int64(1), 0).Return((*types.Part)(nil)).Once()
			}
			if reason == "metadata" {
				store.On("Base").Return(int64(1)).Once()
				store.On("Height").Return(int64(1)).Once()
			}
			r := servingReactor(nil, store)
			require.Nil(t, r.loadCatchupPart(log.NewNopLogger(), &cstypes.RoundState{Height: 2}, prs, 0))
			store.AssertExpectations(t)
		})
	}
}

func TestNativeServingVoteCompletion(t *testing.T) {
	for _, reason := range []string{"missing", "empty", "queue_full", "flushed"} {
		t.Run(reason, func(t *testing.T) {
			lease := &servingLease{}
			policy := &acceptedPolicy{lease: lease}
			r := servingReactor(policy, nil)
			peer := &trackedServingPeer{reject: reason == "queue_full"}
			ps := NewPeerState(peer)
			ps.PRS.Height = 1
			ps.PRS.Round = 0
			commit := &types.ExtendedCommit{Height: 1}
			if reason == "queue_full" || reason == "flushed" {
				commit.ExtendedSignatures = []types.ExtendedCommitSig{{CommitSig: types.CommitSig{BlockIDFlag: types.BlockIDFlagCommit, ValidatorAddress: make([]byte, 20), Signature: make([]byte, 64)}}}
			}
			load := func() types.VoteSetReader {
				require.Len(t, policy.requests, 1)
				if reason == "missing" {
					return nil
				}
				return commit
			}
			require.Equal(t, reason == "flushed", r.sendCatchupVote(peer, ps, 1, load))
			if reason == "flushed" {
				require.Empty(t, lease.results)
				require.NotNil(t, peer.done)
				peer.done(true)
				require.True(t, ps.PRS.Precommits.GetIndex(0))
			}
			require.Equal(t, []bool{reason == "flushed"}, lease.results)
		})
	}
}
