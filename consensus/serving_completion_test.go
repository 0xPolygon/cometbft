package consensus

import (
	"testing"

	cfg "github.com/cometbft/cometbft/config"
	cstypes "github.com/cometbft/cometbft/consensus/types"
	"github.com/cometbft/cometbft/libs/bits"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	cmtcons "github.com/cometbft/cometbft/proto/tendermint/consensus"
	"github.com/cometbft/cometbft/state/mocks"
	"github.com/cometbft/cometbft/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type servingLease struct {
	size    uint64
	results []bool
}

func (l *servingLease) Prepare(n uint64) bool { l.size = n; return true }
func (l *servingLease) Finish(ok bool)        { l.results = append(l.results, ok) }

type acceptedPolicy struct {
	lease    *servingLease
	requests []servebudget.Request
}

func (p *acceptedPolicy) Admit(_ string, r servebudget.Request) (servebudget.Lease, bool) {
	p.requests = append(p.requests, r)
	return p.lease, true
}
func (*acceptedPolicy) Observe(string, servebudget.Evidence) {}

type trackedServingPeer struct {
	servingPeer
	message p2p.Envelope
	done    func(bool)
	reject  bool
}

func (p *trackedServingPeer) TrySendTracked(e p2p.Envelope, done func(bool)) bool {
	if p.reject {
		return false
	}
	p.message = e
	p.done = done
	return true
}

func servingReactor(policy servebudget.Policy, store *mocks.BlockStore) *Reactor {
	config := cfg.DefaultP2PConfig()
	config.ServingPolicy = policy
	consensusConfig := cfg.DefaultConsensusConfig()
	consensusConfig.PeerGossipSleepDuration = 0
	r := &Reactor{conS: &State{config: consensusConfig, blockStore: store}}
	r.BaseReactor = *p2p.NewBaseReactor("test", r)
	r.SetSwitch(p2p.NewSwitch(config, nil))
	return r
}

func TestNativeServingCatchupDenial(t *testing.T) {
	policy := &deniedPolicy{}
	r := servingReactor(policy, nil)
	require.Nil(t, r.loadCatchupMajority(servingPeer{}, 1))
	prs := &cstypes.PeerRoundState{Height: 1, ProposalBlockParts: bits.NewBitArray(1)}
	r.gossipDataForCatchup(log.NewNopLogger(), &cstypes.RoundState{Height: 2}, prs, nil, servingPeer{})
	require.Equal(t, 2, policy.calls)
}

func TestNativeServingCatchupPart(t *testing.T) {
	for _, outcome := range []string{"flushed", "failed_flush", "queue_full"} {
		t.Run(outcome, func(t *testing.T) {
			parts := types.NewPartSetFromData([]byte("block data"), types.PartSizeBytes)
			lease := &servingLease{}
			policy := &acceptedPolicy{lease: lease}
			store := &mocks.BlockStore{}
			store.On("LoadBlockMeta", int64(1)).Run(func(mock.Arguments) { require.Len(t, policy.requests, 1) }).Return(&types.BlockMeta{BlockID: types.BlockID{PartSetHeader: parts.Header()}}).Once()
			store.On("LoadBlockPart", int64(1), 0).Return(parts.GetPart(0)).Once()
			r := servingReactor(policy, store)
			peer := &trackedServingPeer{reject: outcome == "queue_full"}
			ps := NewPeerState(peer)
			ps.PRS.Height = 1
			ps.PRS.ProposalBlockPartSetHeader = parts.Header()
			ps.PRS.ProposalBlockParts = bits.NewBitArray(1)
			r.gossipDataForCatchup(log.NewNopLogger(), &cstypes.RoundState{Height: 2}, ps.GetRoundState(), ps, peer)
			require.Equal(t, servebudget.Catchup, policy.requests[0].Family)
			require.Equal(t, uint64(1), policy.requests[0].Height)
			if peer.done != nil {
				require.Empty(t, lease.results)
				msg := peer.message.Message.(*cmtcons.BlockPart)
				require.Equal(t, int64(1), msg.Height)
				require.Equal(t, []byte(parts.GetPart(0).Bytes), msg.Part.Bytes)
				require.Equal(t, uint64(proto.Size(msg.Wrap())), lease.size)
				peer.done(outcome == "flushed")
			}
			require.Equal(t, []bool{outcome == "flushed"}, lease.results)
			store.AssertExpectations(t)
		})
	}
}

func TestNativeServingCatchupMajority(t *testing.T) {
	for _, latest := range []bool{false, true} {
		t.Run(map[bool]string{true: "latest", false: "historical"}[latest], func(t *testing.T) {
			lease := &servingLease{}
			policy := &acceptedPolicy{lease: lease}
			store := &mocks.BlockStore{}
			height := int64(2)
			method := "LoadBlockCommit"
			if latest {
				height = 1
				method = "LoadSeenCommit"
			}
			store.On("Height").Run(func(mock.Arguments) { require.Len(t, policy.requests, 1) }).Return(height).Once()
			commit := &types.Commit{Height: 1}
			store.On(method, int64(1)).Return(commit).Once()
			r := servingReactor(policy, store)
			require.Same(t, commit, r.loadCatchupMajority(servingPeer{}, 1))
			require.Equal(t, servebudget.Catchup, policy.requests[0].Family)
			require.Equal(t, []bool{false}, lease.results, "read-only reservation must be released without transfer credit")
			require.Zero(t, lease.size)
			store.AssertExpectations(t)
		})
	}
}
