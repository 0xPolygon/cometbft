package consensus

import (
	"bytes"
	"testing"

	cstypes "github.com/cometbft/cometbft/consensus/types"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p/servebudget"
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
	got, admitted := r.loadCatchupMeta(servingPeer{}, 1)
	require.Same(t, meta, got)
	require.True(t, admitted)
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

func TestNativeServingIdleLastCommit(t *testing.T) {
	policy := &deniedPolicy{}
	r := servingReactor(policy, nil)
	peer := &trackedServingPeer{}
	ps := NewPeerState(peer)
	ps.PRS.Height = 1
	ps.PRS.Round = 0
	empty := &types.ExtendedCommit{Height: 1}
	for i := 0; i < 100; i++ {
		require.False(t, r.sendLastCommit(peer, ps, empty))
	}
	require.Zero(t, policy.calls, "idle in-memory catch-up must not consume serving admissions")
}

func TestNativeServingLastCommitCompletion(t *testing.T) {
	for _, outcome := range []string{"flushed", "failed_flush", "queue_full"} {
		t.Run(outcome, func(t *testing.T) {
			lease := &servingLease{}
			policy := &acceptedPolicy{lease: lease}
			r := servingReactor(policy, nil)
			peer := &trackedServingPeer{reject: outcome == "queue_full"}
			ps := NewPeerState(peer)
			ps.PRS.Height = 1
			ps.PRS.Round = 0
			commit := &types.ExtendedCommit{Height: 1, ExtendedSignatures: []types.ExtendedCommitSig{{CommitSig: types.CommitSig{BlockIDFlag: types.BlockIDFlagCommit, ValidatorAddress: make([]byte, 20), Signature: make([]byte, 64)}}}}
			require.Equal(t, outcome != "queue_full", r.sendLastCommit(peer, ps, commit))
			require.Len(t, policy.requests, 1)
			require.Equal(t, uint64(maxMsgSize), policy.requests[0].MaxBytes)
			if outcome != "queue_full" {
				require.Empty(t, lease.results)
				peer.done(outcome == "flushed")
				require.True(t, ps.PRS.Precommits.GetIndex(0))
				require.False(t, r.sendLastCommit(peer, ps, commit))
				require.Len(t, policy.requests, 1, "already shared votes must not spend more work")
			} else {
				require.False(t, ps.PRS.Precommits.GetIndex(0))
			}
			require.Equal(t, []bool{outcome == "flushed"}, lease.results)
		})
	}
}

func TestNativeServingLastCommitDenial(t *testing.T) {
	policy := &deniedPolicy{}
	r := servingReactor(policy, nil)
	peer := &trackedServingPeer{}
	ps := NewPeerState(peer)
	ps.PRS.Height = 1
	ps.PRS.Round = 0
	require.False(t, r.sendLastCommit(peer, ps, nil))
	require.Zero(t, policy.calls)
	commit := &types.ExtendedCommit{Height: 1, ExtendedSignatures: []types.ExtendedCommitSig{{CommitSig: types.CommitSig{BlockIDFlag: types.BlockIDFlagCommit, ValidatorAddress: make([]byte, 20), Signature: make([]byte, 64)}}}}
	require.False(t, r.sendLastCommit(peer, ps, commit))
	require.Equal(t, 1, policy.calls)
	require.False(t, ps.PRS.Precommits.GetIndex(0))
	require.Nil(t, peer.done)
}

func TestNativeServingCatchupMetaLogging(t *testing.T) {
	for _, outcome := range []string{"denied", "missing", "present"} {
		t.Run(outcome, func(t *testing.T) {
			var policy servebudget.Policy = &acceptedPolicy{lease: &servingLease{}}
			store := &mocks.BlockStore{}
			parts := types.NewPartSetFromData([]byte("block"), types.PartSizeBytes)
			if outcome == "denied" {
				policy = &deniedPolicy{}
			} else {
				var meta *types.BlockMeta
				if outcome == "present" {
					meta = &types.BlockMeta{BlockID: types.BlockID{PartSetHeader: parts.Header()}}
				} else {
					store.On("Base").Return(int64(1)).Once()
					store.On("Height").Return(int64(2)).Once()
				}
				store.On("LoadBlockMeta", int64(1)).Return(meta).Once()
			}
			r := servingReactor(policy, store)
			var output bytes.Buffer
			peer := &trackedServingPeer{}
			ps := NewPeerState(peer)
			require.Equal(t, outcome == "present", r.initCatchupParts(log.NewTMJSONLogger(&output), peer, ps, 1))
			require.Equal(t, outcome == "missing", bytes.Contains(output.Bytes(), []byte("Failed to load block meta")))
			if outcome != "missing" {
				require.Empty(t, output.String())
			}
			if outcome == "present" {
				require.Equal(t, parts.Header(), ps.GetRoundState().ProposalBlockPartSetHeader)
			}
			store.AssertExpectations(t)
		})
	}
}
