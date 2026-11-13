package blocksync

import (
	"sync/atomic"
	"testing"
	"time"

	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/stretchr/testify/require"
)

type deferredSendPeer struct {
	*responseBlockPeer
	attempts atomic.Int64
}

func (p *deferredSendPeer) TrySend(e p2p.Envelope) bool {
	if p.attempts.Add(1) == 1 {
		return false
	}
	return p.responseBlockPeer.TrySend(e)
}

func TestDeferredBlockRetriesRejectedSend(t *testing.T) {
	doc, vals := genesisDocWithValsPowers([]int64{10})
	pair := newReactor(t, log.NewNopLogger(), doc, vals, 2)
	t.Cleanup(func() { require.NoError(t, pair.app.Stop()) })
	r := pair.reactor.Reactor
	config := cfg.DefaultP2PConfig()
	policy := &selectiveBlockPolicy{}
	config.ServingPolicy = policy
	r.SetSwitch(p2p.NewSwitch(config, nil))
	d := newDeferredBlocks(r, policy)
	t.Cleanup(d.stop)
	peer := &deferredSendPeer{responseBlockPeer: &responseBlockPeer{blockServingPeer: newBlockServingPeer(t, false), heights: make(chan int64, 1)}}
	require.True(t, d.enqueue(peer, 2, false))
	select {
	case height := <-peer.heights:
		require.Equal(t, int64(2), height)
	case <-time.After(time.Second):
		t.Fatal("request was discarded after the transport rejected its response")
	}
	require.Equal(t, int64(2), peer.attempts.Load())
}
