package blocksync

import (
	"sync/atomic"
	"testing"
	"time"

	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	"github.com/stretchr/testify/require"
)

type pausedServingPolicy struct{ ready atomic.Bool }

func (p *pausedServingPolicy) Admit(string, servebudget.Request) (servebudget.Lease, bool) {
	return nil, p.ready.Load()
}

func (p *pausedServingPolicy) Retry(id string, req servebudget.Request) (servebudget.Lease, bool) {
	return p.Admit(id, req)
}
func (*pausedServingPolicy) Observe(string, servebudget.Evidence) {}

func TestServingDeferredPeerSync(t *testing.T) {
	doc, vals := genesisDocWithValsPowers([]int64{10})
	pairs := []ReactorPair{
		newReactor(t, log.NewNopLogger(), doc, vals, 10),
		newReactor(t, log.NewNopLogger(), doc, vals, 0),
	}
	for _, pair := range pairs {
		t.Cleanup(func() { require.NoError(t, pair.app.Stop()) })
	}
	pairs[0].reactor.blockSync.Store(false)
	policy := &pausedServingPolicy{}
	config := cfg.DefaultP2PConfig()
	config.ServingPolicy = policy
	switches := p2p.MakeConnectedSwitches(config, 2, func(i int, sw *p2p.Switch) *p2p.Switch {
		sw.AddReactor("BLOCKSYNC", pairs[i].reactor.Reactor)
		return sw
	}, func([]*p2p.Switch, int, int) {})
	require.NoError(t, switches[1].DialPeerWithAddress(switches[0].NetAddress()))
	for _, sw := range switches {
		t.Cleanup(func() { require.NoError(t, sw.Stop()) })
	}
	pool := pairs[1].reactor.pool
	id := switches[0].NodeInfo().ID()
	require.Eventually(t, func() bool {
		pool.mtx.Lock()
		defer pool.mtx.Unlock()
		peer := pool.peers[id]
		return peer != nil && len(peer.deferrals) == 10
	}, peerConnWait+2*time.Second, time.Millisecond)
	time.Sleep((requestRetrySeconds + 1) * time.Second)
	pool.mtx.Lock()
	peer := pool.peers[id]
	pending := int32(0)
	if peer != nil {
		pending = peer.numPending
	}
	pool.mtx.Unlock()
	require.NotNil(t, peer, "serving deferral must survive the normal inactivity timeout")
	require.Equal(t, int32(10), pending, "retry timer must retain each original assignment")
	policy.ready.Store(true)
	require.Eventually(t, func() bool {
		return pairs[1].reactor.store.Height() >= 9
	}, 5*time.Second, time.Millisecond)
	require.Equal(t, 1, switches[1].Peers().Size())
}
