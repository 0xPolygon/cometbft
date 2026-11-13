package blocksync

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	bc "github.com/cometbft/cometbft/proto/tendermint/blocksync"
	"github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

type limitedServingPolicy struct {
	mu      sync.Mutex
	tokens  float64
	last    time.Time
	refused atomic.Int64
}

func (p *limitedServingPolicy) Admit(string, servebudget.Request) (servebudget.Lease, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	p.tokens = min(20, p.tokens+now.Sub(p.last).Seconds()*32/3)
	p.last = now
	if p.tokens < 1 {
		p.refused.Add(1)
		return nil, false
	}
	p.tokens--
	return nil, true
}
func (*limitedServingPolicy) Observe(string, servebudget.Evidence) {}

func (p *limitedServingPolicy) Retry(id string, req servebudget.Request) (servebudget.Lease, bool) {
	return p.Admit(id, req)
}

type poolServingPeer struct {
	*blockServingPeer
	pool   *BlockPool
	errors chan error
}

func (p *poolServingPeer) TrySend(e p2p.Envelope) bool {
	response, ok := e.Message.(*bc.BlockResponse)
	if !ok {
		return true
	}
	block, err := types.BlockFromProto(response.Block)
	if err == nil {
		err = p.pool.AddBlock(p.ID(), block, nil, response.Block.Size())
	}
	if err != nil {
		p.errors <- err
	}
	return err == nil
}

func TestServingBudgetKeepsBlockPoolProgress(t *testing.T) {
	const blocks = 500
	doc, vals := genesisDocWithValsPowers([]int64{10})
	pair := newReactor(t, log.NewNopLogger(), doc, vals, blocks)
	t.Cleanup(func() { require.NoError(t, pair.app.Stop()) })
	server := pair.reactor.Reactor
	server.blockSync.Store(false)
	policy := &limitedServingPolicy{tokens: 20, last: time.Now()}
	config := cfg.DefaultP2PConfig()
	config.ServingPolicy = policy
	server.SetSwitch(p2p.NewSwitch(config, nil))
	require.NoError(t, server.Start())
	t.Cleanup(func() { require.NoError(t, server.Stop()) })
	requests := make(chan BlockRequest, 100)
	errors := make(chan peerError, 100)
	pool := NewBlockPool(1, requests, errors)
	peer := &poolServingPeer{blockServingPeer: newBlockServingPeer(t, false), pool: pool, errors: make(chan error, 100)}
	pool.SetPeerRange(peer.ID(), 1, blocks)
	require.NoError(t, pool.Start())
	t.Cleanup(func() { pool.RemovePeer(peer.ID()); require.NoError(t, pool.Stop()) })
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(65 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case req := <-requests:
			server.Receive(p2p.Envelope{ChannelID: BlocksyncChannel, Src: peer, Message: &bc.BlockRequest{Height: req.Height}})
		case err := <-errors:
			t.Fatalf("requesting BlockPool rejected a budget-limited server: %v", err)
		case err := <-peer.errors:
			t.Fatal(err)
		case <-tick.C:
			first, _, _ := pool.PeekTwoBlocks()
			if first != nil {
				pool.PopRequest()
			}
			height, _, _ := pool.GetStatus()
			if height > blocks {
				require.Positive(t, policy.refused.Load())
				return
			}
		case <-deadline.C:
			height, _, _ := pool.GetStatus()
			t.Fatalf("sync stalled at height %d", height)
		}
	}
}
