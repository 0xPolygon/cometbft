package statesync

import (
	"errors"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	ss "github.com/cometbft/cometbft/proto/tendermint/statesync"
	"github.com/cometbft/cometbft/proxy/mocks"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type servingLease struct {
	size    uint64
	allow   bool
	results []bool
}

func (l *servingLease) Prepare(n uint64) bool { l.size = n; return l.allow }
func (l *servingLease) Finish(ok bool)        { l.results = append(l.results, ok) }

type acceptedPolicy struct {
	lease    *servingLease
	requests []servebudget.Request
}

func (p *acceptedPolicy) Admit(_ string, req servebudget.Request) (servebudget.Lease, bool) {
	p.requests = append(p.requests, req)
	return p.lease, true
}
func (*acceptedPolicy) Observe(string, servebudget.Evidence) {}

type trackedServingPeer struct {
	servingPeer
	callbacks []func(bool)
	messages  []p2p.Envelope
	failAt    int
}

func (p *trackedServingPeer) TrySendTracked(e p2p.Envelope, done func(bool)) bool {
	if p.failAt > 0 && len(p.messages)+1 == p.failAt {
		return false
	}
	p.messages = append(p.messages, e)
	p.callbacks = append(p.callbacks, done)
	return true
}

func TestNativeServingCompletion(t *testing.T) {
	for _, family := range []string{"chunk", "snapshots"} {
		for _, outcome := range []string{"flushed", "failed_flush", "queue_full", "prepare_denied", "abci_error"} {
			t.Run(family+"/"+outcome, func(t *testing.T) { testServingCompletion(t, family, outcome) })
		}
	}
}

func testServingCompletion(t *testing.T, family, outcome string) {
	t.Helper()
	lease := &servingLease{allow: outcome != "prepare_denied"}
	policy := &acceptedPolicy{lease: lease}
	config := cfg.DefaultP2PConfig()
	config.ServingPolicy = policy
	app := &mocks.AppConnSnapshot{}
	peer := &trackedServingPeer{}
	var loadErr error
	if outcome == "abci_error" {
		loadErr = errors.New("snapshot store unavailable")
	}
	var expected []proto.Message
	var request proto.Message
	channel := ChunkChannel
	if family == "chunk" {
		request = &ss.ChunkRequest{Height: 1, Format: 2, Index: 3}
		expected = []proto.Message{&ss.ChunkResponse{Height: 1, Format: 2, Index: 3, Chunk: []byte{1, 2, 3}}}
		app.On("LoadSnapshotChunk", mock.Anything, &abci.RequestLoadSnapshotChunk{Height: 1, Format: 2, Chunk: 3}).Run(func(mock.Arguments) { require.Len(t, policy.requests, 1) }).Return(&abci.ResponseLoadSnapshotChunk{Chunk: []byte{1, 2, 3}}, loadErr).Once()
	} else {
		request = &ss.SnapshotsRequest{}
		channel = SnapshotChannel
		snapshots := []*abci.Snapshot{{Height: 2, Format: 1, Chunks: 1, Hash: []byte{2}}, {Height: 1, Format: 1, Chunks: 1, Hash: []byte{1}}}
		for _, s := range snapshots {
			expected = append(expected, &ss.SnapshotsResponse{Height: s.Height, Format: s.Format, Chunks: s.Chunks, Hash: s.Hash})
		}
		app.On("ListSnapshots", mock.Anything, mock.Anything).Run(func(mock.Arguments) { require.Len(t, policy.requests, 1) }).Return(&abci.ResponseListSnapshots{Snapshots: snapshots}, loadErr).Once()
	}
	if outcome == "queue_full" {
		peer.failAt = len(expected)
	}
	r := NewReactor(*cfg.DefaultStateSyncConfig(), app, nil, NopMetrics())
	r.SetSwitch(p2p.NewSwitch(config, nil))
	require.NoError(t, r.Start())
	t.Cleanup(func() { require.NoError(t, r.Stop()) })
	r.Receive(p2p.Envelope{Src: peer, ChannelID: channel, Message: request})
	if family == "chunk" {
		require.Equal(t, []servebudget.Request{{Family: servebudget.Chunk, Height: 1, Format: 2, Index: 3, MaxBytes: uint64(chunkMsgSize)}}, policy.requests)
	} else {
		require.Equal(t, []servebudget.Request{{Family: servebudget.Snapshot, MaxBytes: uint64(recentSnapshots * snapshotMsgSize)}}, policy.requests)
	}
	if loadErr == nil {
		var size uint64
		for _, msg := range expected {
			size += uint64(proto.Size(msg.(p2p.Wrapper).Wrap()))
		}
		require.Equal(t, size, lease.size)
	}
	for i, msg := range peer.messages {
		require.Equal(t, expected[i], msg.Message)
	}
	for _, done := range peer.callbacks {
		require.Empty(t, lease.results, "queued frames still own the lease")
		done(outcome != "failed_flush")
	}
	require.Equal(t, []bool{outcome == "flushed"}, lease.results)
	app.AssertExpectations(t)
}

func (p *trackedServingPeer) TrySend(e p2p.Envelope) bool {
	p.messages = append(p.messages, e)
	return true
}

func TestNativeServingMissingChunk(t *testing.T) {
	lease := &servingLease{allow: true}
	policy := &acceptedPolicy{lease: lease}
	config := cfg.DefaultP2PConfig()
	config.ServingPolicy = policy
	app := &mocks.AppConnSnapshot{}
	app.On("LoadSnapshotChunk", mock.Anything, &abci.RequestLoadSnapshotChunk{Height: 1, Format: 2, Chunk: 3}).Return(&abci.ResponseLoadSnapshotChunk{}, nil).Once()
	r := NewReactor(*cfg.DefaultStateSyncConfig(), app, nil, NopMetrics())
	r.SetSwitch(p2p.NewSwitch(config, nil))
	peer := &trackedServingPeer{}
	r.serveChunk(p2p.Envelope{Src: peer}, &ss.ChunkRequest{Height: 1, Format: 2, Index: 3})
	require.Equal(t, []p2p.Envelope{{ChannelID: ChunkChannel, Message: &ss.ChunkResponse{Height: 1, Format: 2, Index: 3, Missing: true}}}, peer.messages)
	require.Empty(t, peer.callbacks, "missing chunks must not gain transfer completion credit")
	require.Zero(t, lease.size)
	require.Equal(t, []bool{false}, lease.results)
	app.AssertExpectations(t)
}
