package blocksync

import (
	"net"
	"testing"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/go-kit/kit/metrics"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/p2p"
	p2pmock "github.com/cometbft/cometbft/p2p/mock"
	bcproto "github.com/cometbft/cometbft/proto/tendermint/blocksync"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
)

type recordingCounter struct{ value float64 }

func (c *recordingCounter) With(...string) metrics.Counter { return c }
func (c *recordingCounter) Add(n float64)                  { c.value += n }

type blockServingPeer struct {
	p2p.Peer
	full bool
}

func (p *blockServingPeer) SendQueueFull(chID byte) bool {
	return chID == BlocksyncChannel && p.full
}

func TestBlockServingQueueFull(t *testing.T) {
	t.Parallel()
	legacyPeer := p2pmock.NewPeer(nil)
	t.Cleanup(func() { require.NoError(t, legacyPeer.Stop()) })
	for _, tc := range []struct {
		name string
		peer p2p.Peer
		full bool
	}{
		{"available", &blockServingPeer{}, false},
		{"full", &blockServingPeer{full: true}, true},
		{"unsupported", legacyPeer, false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.full, blockQueueFull(tc.peer))
		})
	}
}

func TestBlockServingQueueDropsBeforePreparation(t *testing.T) {
	t.Parallel()
	drops := &recordingCounter{}
	r := NewReactor(sm.State{InitialHeight: 1}, nil, &store.BlockStore{}, false, NopMetrics(), 0,
		WithSendQueueFullDrops(drops))
	r.servingBudget = nil
	peer := newBlockServingPeer(t, true)
	request := &bcproto.BlockRequest{Height: 17}
	r.Receive(p2p.Envelope{Src: peer, Message: request})
	require.False(t, r.respondToPeer(request, peer))
	require.Equal(t, float64(2), drops.value)
	require.Len(t, r.reqLimiter.counts[peer.ID()].timestamps, 2)
	require.Len(t, r.ipLimiter.counts[ipRateLimitKey(peer.RemoteIP())].timestamps, 2)
}

func TestBlockServingQueueDrain(t *testing.T) {
	t.Parallel()
	db := dbm.NewMemDB()
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	drops := &recordingCounter{}
	r := NewReactor(sm.State{InitialHeight: 1}, nil, store.NewBlockStore(db), false, NopMetrics(), 0,
		WithSendQueueFullDrops(drops))
	peer := newBlockServingPeer(t, true)
	request := &bcproto.BlockRequest{Height: 17}
	require.True(t, r.respondToPeer(request, newBlockServingPeer(t, false)))
	require.False(t, r.respondToPeer(request, peer))
	require.Equal(t, float64(1), drops.value)
	peer.full = false
	require.True(t, r.respondToPeer(request, peer))
	require.True(t, r.respondToPeer(request, peer.Peer))
	require.Equal(t, float64(1), drops.value)
}

func TestBlockServingFullQueuePeerBan(t *testing.T) {
	t.Parallel()
	drops := &recordingCounter{}
	peerDrops := &recordingCounter{}
	m := NopMetrics()
	m.PeerBlockRequestsDropped = peerDrops
	r := NewReactor(sm.State{InitialHeight: 1}, nil, &store.BlockStore{}, false, m, 0,
		WithSendQueueFullDrops(drops))
	r.reqLimiter.maxRequests = 2
	peer := newBlockServingPeer(t, true)
	request := &bcproto.BlockRequest{Height: 17}
	for i := 0; i < 3; i++ {
		require.False(t, r.respondToPeer(request, peer))
	}
	require.True(t, r.reqLimiter.isBanned(peer.ID()))
	require.Equal(t, float64(2), drops.value)
	require.Equal(t, float64(1), peerDrops.value)
	peer.full = false
	require.False(t, r.respondToPeer(request, peer))
	require.Equal(t, float64(2), drops.value)
	require.Equal(t, float64(2), peerDrops.value)
}

func TestBlockServingFullQueueSubnetBan(t *testing.T) {
	t.Parallel()
	drops := &recordingCounter{}
	subnetDrops := &recordingCounter{}
	m := NopMetrics()
	m.SubnetBlockRequestsDropped = subnetDrops
	r := NewReactor(sm.State{InitialHeight: 1}, nil, &store.BlockStore{}, false, m, 0,
		WithSendQueueFullDrops(drops))
	r.ipLimiter.maxRequests = 2
	request := &bcproto.BlockRequest{Height: 17}
	for i := 0; i < 3; i++ {
		require.False(t, r.respondToPeer(request, newBlockServingPeer(t, true)))
	}
	peer := newBlockServingPeer(t, false)
	require.True(t, r.ipLimiter.isBanned(ipRateLimitKey(peer.RemoteIP())))
	require.Equal(t, float64(2), drops.value)
	require.Equal(t, float64(1), subnetDrops.value)
	require.False(t, r.respondToPeer(request, peer))
	require.Equal(t, float64(2), drops.value)
	require.Equal(t, float64(2), subnetDrops.value)
	require.NotContains(t, r.reqLimiter.counts, peer.ID())
}

func TestBlockServingPersistentQueueFull(t *testing.T) {
	t.Parallel()
	drops := &recordingCounter{}
	exempt := &recordingCounter{}
	m := NopMetrics()
	m.PersistentPeerRequestsExempted = exempt
	r := NewReactor(sm.State{InitialHeight: 1}, nil, &store.BlockStore{}, false, m, 0,
		WithSendQueueFullDrops(drops))
	r.reqLimiter.maxRequests, r.ipLimiter.maxRequests = 0, 0
	peer := newBlockServingPeer(t, true)
	peer.Peer.(*p2pmock.Peer).Persistent = true
	require.False(t, r.respondToPeer(&bcproto.BlockRequest{Height: 17}, peer))
	require.Equal(t, float64(1), drops.value)
	require.Equal(t, float64(1), exempt.value)
	require.Empty(t, r.reqLimiter.counts)
	require.Empty(t, r.ipLimiter.counts)
}

func TestBlockServingQueueCounterOptional(t *testing.T) {
	t.Parallel()
	r := NewReactor(sm.State{InitialHeight: 1}, nil, &store.BlockStore{}, false, NopMetrics(), 0)
	peer := newBlockServingPeer(t, true)
	require.False(t, r.respondToPeer(&bcproto.BlockRequest{Height: 17}, peer))
	WithSendQueueFullDrops(nil)(r)
	require.False(t, r.respondToPeer(&bcproto.BlockRequest{Height: 17}, peer))
}

func newBlockServingPeer(t *testing.T, full bool) *blockServingPeer {
	t.Helper()
	peer := &blockServingPeer{Peer: p2pmock.NewPeer(net.ParseIP("203.0.113.7")), full: full}
	t.Cleanup(func() { require.NoError(t, peer.Stop()) })
	return peer
}
