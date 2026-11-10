package blocksync

import (
	"sync/atomic"
	"testing"
	"time"

	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	bc "github.com/cometbft/cometbft/proto/tendermint/blocksync"
	"github.com/stretchr/testify/require"
)

type deferredTestPolicy struct {
	initial atomic.Int64
	retries atomic.Int64
}

func (p *deferredTestPolicy) Admit(string, servebudget.Request) (servebudget.Lease, bool) {
	p.initial.Add(1)
	return nil, false
}

func (p *deferredTestPolicy) Retry(string, servebudget.Request) (servebudget.Lease, bool) {
	p.retries.Add(1)
	return nil, false
}
func (*deferredTestPolicy) Observe(string, servebudget.Evidence) {}

func TestDeferredBlockBounds(t *testing.T) {
	policy := &deferredTestPolicy{}
	d := newDeferredBlocks(&Reactor{}, policy)
	t.Cleanup(d.stop)
	peer := newBlockServingPeer(t, false)
	require.True(t, d.enqueue(peer, 1, false))
	for range 30 {
		require.True(t, d.enqueue(peer, 1, false))
	}
	require.Eventually(t, func() bool { return policy.retries.Load() > 0 }, time.Second, time.Millisecond)
	require.Equal(t, int64(1), policy.initial.Load())
	for height := int64(2); height <= maxPendingRequestsPerPeer+1; height++ {
		require.True(t, d.enqueue(peer, height, false))
	}
	require.False(t, d.enqueue(peer, maxPendingRequestsPerPeer+2, false))
	d.stop()
	require.False(t, d.enqueue(peer, 100, false))
	require.Zero(t, d.workers)
}

type sameIDPeer struct {
	*blockServingPeer
	id p2p.ID
}

func (p *sameIDPeer) ID() p2p.ID { return p.id }

func TestDeferredBlockReconnect(t *testing.T) {
	policy := &deferredTestPolicy{}
	d := newDeferredBlocks(&Reactor{}, policy)
	t.Cleanup(d.stop)
	old := newBlockServingPeer(t, false)
	current := &sameIDPeer{blockServingPeer: newBlockServingPeer(t, false), id: old.ID()}
	require.True(t, d.enqueue(old, 1, false))
	require.Eventually(t, func() bool { return policy.initial.Load() == 1 }, time.Second, time.Millisecond)
	require.False(t, d.enqueue(current, 2, false))
	d.remove(old)
	require.True(t, d.enqueue(current, 2, false))
	d.remove(old)
	require.Eventually(t, func() bool { return policy.initial.Load() == 2 }, time.Second, time.Millisecond)
	require.True(t, d.enqueue(current, 3, false))
	d.remove(current)
	require.Eventually(t, func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return len(d.peers) == 0 && d.workers == 0
	}, time.Second, time.Millisecond)
}

func TestDeferredBlockWorkerLimit(t *testing.T) {
	d := newDeferredBlocks(&Reactor{}, &deferredTestPolicy{})
	t.Cleanup(d.stop)
	d.workers = maxDeferredPeers - 1
	peer := newBlockServingPeer(t, false)
	require.True(t, d.enqueue(peer, 1, false))
	require.False(t, d.enqueue(newBlockServingPeer(t, false), 1, false))
	require.True(t, d.enqueue(peer, 2, false))
	d.stop()
	require.Equal(t, maxDeferredPeers-1, d.workers)
}

type cancelledAdmissionPolicy struct {
	deferredTestPolicy
	entered, release chan struct{}
	lease            *blockLease
}

func (p *cancelledAdmissionPolicy) Admit(string, servebudget.Request) (servebudget.Lease, bool) {
	close(p.entered)
	<-p.release
	return p.lease, true
}

func TestDeferredBlockCancellationReleasesAdmission(t *testing.T) {
	policy := &cancelledAdmissionPolicy{entered: make(chan struct{}), release: make(chan struct{}), lease: &blockLease{}}
	d := newDeferredBlocks(&Reactor{}, policy)
	peer := newBlockServingPeer(t, false)
	require.True(t, d.enqueue(peer, 1, false))
	<-policy.entered
	d.remove(peer)
	close(policy.release)
	d.stop()
	require.Equal(t, []bool{false}, policy.lease.results)
}

type selectiveBlockPolicy struct{ deferredTestPolicy }

func (p *selectiveBlockPolicy) Admit(id string, req servebudget.Request) (servebudget.Lease, bool) {
	if req.Height == 1 {
		return p.deferredTestPolicy.Admit(id, req)
	}
	return nil, true
}

func (p *selectiveBlockPolicy) Retry(id string, req servebudget.Request) (servebudget.Lease, bool) {
	if req.Height == 1 {
		return p.deferredTestPolicy.Retry(id, req)
	}
	return nil, true
}

type responseBlockPeer struct {
	*blockServingPeer
	heights chan int64
}

func (p *responseBlockPeer) TrySend(e p2p.Envelope) bool {
	if block, ok := e.Message.(*bc.BlockResponse); ok {
		p.heights <- block.Block.Header.Height
	}
	return true
}

func TestDeferredBlockDispatchAndLifecycle(t *testing.T) {
	doc, vals := genesisDocWithValsPowers([]int64{10})
	pair := newReactor(t, log.NewNopLogger(), doc, vals, 2)
	t.Cleanup(func() { require.NoError(t, pair.app.Stop()) })
	r := pair.reactor.Reactor
	r.blockSync = false
	policy := &selectiveBlockPolicy{}
	config := cfg.DefaultP2PConfig()
	config.ServingPolicy = policy
	r.SetSwitch(p2p.NewSwitch(config, nil))
	require.NoError(t, r.Start())
	t.Cleanup(func() {
		if r.IsRunning() {
			require.NoError(t, r.Stop())
		}
	})
	peer := &responseBlockPeer{blockServingPeer: newBlockServingPeer(t, false), heights: make(chan int64, 2)}
	for _, height := range []int64{1, 2} {
		r.Receive(p2p.Envelope{ChannelID: BlocksyncChannel, Src: peer, Message: &bc.BlockRequest{Height: height}})
	}
	select {
	case height := <-peer.heights:
		require.Equal(t, int64(2), height)
	case <-time.After(time.Second):
		t.Fatal("refused height blocked a serviceable block")
	}
	r.RemovePeer(peer, nil)
	require.Eventually(t, func() bool {
		r.deferredBlocks.mu.Lock()
		defer r.deferredBlocks.mu.Unlock()
		return r.deferredBlocks.workers == 0
	}, time.Second, time.Millisecond)
	r.Receive(p2p.Envelope{ChannelID: BlocksyncChannel, Src: peer, Message: &bc.BlockRequest{Height: 1}})
	require.NoError(t, r.Stop())
	require.Zero(t, r.deferredBlocks.workers)
}

func TestDeferredBlockLegacyDispatch(t *testing.T) {
	doc, vals := genesisDocWithValsPowers([]int64{10})
	pair := newReactor(t, log.NewNopLogger(), doc, vals, 1)
	t.Cleanup(func() { require.NoError(t, pair.app.Stop()) })
	peer := &responseBlockPeer{blockServingPeer: newBlockServingPeer(t, false), heights: make(chan int64, 1)}
	pair.reactor.Reactor.Receive(p2p.Envelope{ChannelID: BlocksyncChannel, Src: peer, Message: &bc.BlockRequest{Height: 1}})
	select {
	case height := <-peer.heights:
		require.Equal(t, int64(1), height)
	default:
		t.Fatal("legacy serving was not dispatched")
	}
}

type quietBlockPeer struct {
	*blockServingPeer
	quit   chan struct{}
	full   atomic.Bool
	checks atomic.Int64
}

func (p *quietBlockPeer) Quit() <-chan struct{}   { return p.quit }
func (p *quietBlockPeer) SendQueueFull(byte) bool { p.checks.Add(1); return p.full.Load() }

func TestDeferredBlockTransportBackpressure(t *testing.T) {
	policy := &deferredTestPolicy{}
	d := newDeferredBlocks(&Reactor{}, policy)
	t.Cleanup(d.stop)
	peer := &quietBlockPeer{blockServingPeer: newBlockServingPeer(t, false), quit: make(chan struct{})}
	peer.full.Store(true)
	require.True(t, d.enqueue(peer, 1, false))
	require.Eventually(t, func() bool { return peer.checks.Load() > 0 }, time.Second, time.Millisecond)
	require.Zero(t, policy.initial.Load())
	peer.full.Store(false)
	require.Eventually(t, func() bool { return policy.initial.Load() == 1 && policy.retries.Load() > 0 }, time.Second, time.Millisecond)
	close(peer.quit)
	require.Eventually(t, func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.workers == 0 && len(d.peers) == 0
	}, time.Second, time.Millisecond)
}
