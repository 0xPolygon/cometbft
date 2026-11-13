package p2p

import (
	"testing"

	"github.com/cometbft/cometbft/config"
	"github.com/cosmos/gogoproto/proto"

	"github.com/cometbft/cometbft/p2p/servebudget"
	pp "github.com/cometbft/cometbft/proto/tendermint/p2p"
	"github.com/stretchr/testify/require"
)

type testLease struct {
	size  uint64
	done  []bool
	allow bool
}

func (l *testLease) Prepare(n uint64) bool { l.size = n; return l.allow }
func (l *testLease) Finish(ok bool)        { l.done = append(l.done, ok) }

type trackedPeer struct {
	Peer
	callbacks []func(bool)
	failAt    int
}

func (p *trackedPeer) TrySendTracked(_ Envelope, done func(bool)) bool {
	if p.failAt > 0 && len(p.callbacks)+1 == p.failAt {
		return false
	}
	p.callbacks = append(p.callbacks, done)
	return true
}
func TestServingTrackedBatch(t *testing.T) {
	for _, failAt := range []int{0, 1, 2} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			p := &trackedPeer{failAt: failAt}
			l := &testLease{allow: true}
			e := Envelope{Message: &pp.PexRequest{}}
			require.Equal(t, failAt == 0, SendServing(p, l, e, e))
			require.Positive(t, l.size)
			if len(p.callbacks) > 0 {
				require.Empty(t, l.done)
			}
			for _, done := range p.callbacks {
				done(true)
			}
			require.Equal(t, []bool{failAt == 0}, l.done)
		})
	}
}
func TestServingPrepareDenial(t *testing.T) {
	p := &trackedPeer{}
	l := &testLease{}
	require.False(t, SendServing(p, l, Envelope{Message: &pp.PexRequest{}}))
	require.Empty(t, p.callbacks)
	require.Equal(t, []bool{false}, l.done)
	var sw *Switch
	lease, ok := sw.AdmitServing(nil, servebudget.Request{})
	require.True(t, ok)
	require.Nil(t, lease)
	sw.ObserveServing(nil, servebudget.InvalidResponse)
}

type recordingPolicy struct {
	id       string
	request  servebudget.Request
	evidence servebudget.Evidence
	lease    servebudget.Lease
}

func (p *recordingPolicy) Admit(id string, req servebudget.Request) (servebudget.Lease, bool) {
	p.id, p.request = id, req
	return p.lease, p.lease != nil
}
func (p *recordingPolicy) Observe(id string, evidence servebudget.Evidence) {
	p.id, p.evidence = id, evidence
}

type servingIdentity struct {
	Peer
	sent   int
	accept bool
}

func (*servingIdentity) ID() ID                  { return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
func (p *servingIdentity) TrySend(Envelope) bool { p.sent++; return p.accept }

func TestServingPolicyIdentityAndOwnership(t *testing.T) {
	policy := &recordingPolicy{lease: &testLease{allow: true}}
	cfg := config.DefaultP2PConfig()
	cfg.ServingPolicy = policy
	sw := NewSwitch(cfg, nil)
	peer := &servingIdentity{}
	req := servebudget.Request{Family: servebudget.Chunk, Height: 12, Format: 3, Index: 4, MaxBytes: 1024}
	lease, ok := sw.AdmitServing(peer, req)
	require.True(t, ok)
	require.Same(t, policy.lease, lease)
	require.Equal(t, string(peer.ID()), policy.id)
	require.Equal(t, req, policy.request)
	sw.ObserveServing(peer, servebudget.InvalidResponse)
	require.Equal(t, servebudget.InvalidResponse, policy.evidence)
	FinishServing(lease)
	require.Equal(t, []bool{false}, policy.lease.(*testLease).done)
}

func TestServingUntrackedAndEmpty(t *testing.T) {
	for _, accept := range []bool{false, true} {
		peer := &servingIdentity{accept: accept}
		require.Equal(t, accept, SendServing(peer, nil, Envelope{Message: &pp.PexRequest{}}))
		require.Equal(t, 1, peer.sent)
		lease := &testLease{allow: true}
		require.False(t, SendServing(peer, lease, Envelope{Message: &pp.PexRequest{}}))
		require.Equal(t, []bool{false}, lease.done)
		require.Zero(t, lease.size)
	}
	peer := &trackedPeer{}
	lease := &testLease{allow: true}
	require.False(t, SendServing(peer, lease))
	require.Equal(t, []bool{false}, lease.done)
	require.Empty(t, peer.callbacks)
}

func TestServingPartialFlush(t *testing.T) {
	peer := &trackedPeer{}
	lease := &testLease{allow: true}
	msg := &pp.PexRequest{}
	require.True(t, SendServing(peer, lease, Envelope{Message: msg}, Envelope{Message: msg}))
	require.Equal(t, uint64(2*proto.Size(msg.Wrap())), lease.size)
	peer.callbacks[0](false)
	require.Empty(t, lease.done)
	peer.callbacks[1](true)
	require.Equal(t, []bool{false}, lease.done)
}
