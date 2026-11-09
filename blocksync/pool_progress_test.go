package blocksync

import (
	"testing"
	"time"

	"github.com/cometbft/cometbft/p2p"
	"github.com/stretchr/testify/require"
)

func TestBlockPoolProgressRate(t *testing.T) {
	pool := NewBlockPool(1, nil, nil)
	cases := []struct {
		id            p2p.ID
		bytes, blocks float64
	}{
		{"small-blocks", 1000, 5},
		{"large-blocks", minRecvRate * 2, 0.1},
		{"drip", 1000, 0.1},
		{"byte-floor", minRecvRate, 0.1},
		{"block-floor", 1000, minRecvBlockRate},
		{"warming-up", 1000, -1},
	}
	for _, tc := range cases {
		peer := newBPPeer(pool, tc.id, 1, 100)
		peer.resetMonitor()
		peer.numPending = 1
		pool.peers[tc.id] = peer
	}
	time.Sleep(1100 * time.Millisecond)
	for _, tc := range cases {
		peer := pool.peers[tc.id]
		peer.recvMonitor.Status()
		peer.blockMonitor.Status()
		peer.recvMonitor.SetREMA(tc.bytes)
		if tc.blocks >= 0 {
			peer.blockMonitor.SetREMA(tc.blocks)
		}
	}
	pool.removeTimedoutPeers()
	require.Contains(t, pool.peers, p2p.ID("small-blocks"))
	require.Contains(t, pool.peers, p2p.ID("large-blocks"))
	require.NotContains(t, pool.peers, p2p.ID("drip"))
	require.Contains(t, pool.peers, p2p.ID("byte-floor"))
	require.Contains(t, pool.peers, p2p.ID("block-floor"))
	require.Contains(t, pool.peers, p2p.ID("warming-up"))
}

func TestBlockPoolProgressAccounting(t *testing.T) {
	peer := newBPPeer(NewBlockPool(1, nil, nil), "peer", 1, 100)
	peer.incrPending()
	peer.incrPending()
	defer peer.timeout.Stop()
	peer.decrPending(500)
	require.Equal(t, int32(1), peer.numPending)
	require.Equal(t, int64(1), peer.blockMonitor.Done())
	require.Equal(t, int64(500), peer.recvMonitor.Done())
}
