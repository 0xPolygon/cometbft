package blocksync

import (
	"testing"

	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	bc "github.com/cometbft/cometbft/proto/tendermint/blocksync"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"
)

type blockLease struct {
	size    uint64
	results []bool
}

func (l *blockLease) Prepare(n uint64) bool { l.size = n; return true }
func (l *blockLease) Finish(ok bool)        { l.results = append(l.results, ok) }

type blockPolicy struct {
	lease    *blockLease
	requests []servebudget.Request
}

func (p *blockPolicy) Admit(_ string, r servebudget.Request) (servebudget.Lease, bool) {
	p.requests = append(p.requests, r)
	return p.lease, true
}
func (*blockPolicy) Observe(string, servebudget.Evidence) {}

type trackedBlockPeer struct {
	*blockServingPeer
	message p2p.Envelope
	done    func(bool)
	reject  bool
}

func (p *trackedBlockPeer) TrySendTracked(e p2p.Envelope, done func(bool)) bool {
	if p.reject {
		return false
	}
	p.message = e
	p.done = done
	return true
}
func (p *trackedBlockPeer) TrySend(e p2p.Envelope) bool { p.message = e; return true }

func TestNativeServingBlockCompletion(t *testing.T) {
	for _, kind := range []string{"flushed", "failed_flush", "queue_full", "missing_commit", "missing_block"} {
		t.Run(kind, func(t *testing.T) {
			doc, vals := genesisDocWithValsPowers([]int64{10})
			var opts []reactorOption
			if kind == "missing_commit" {
				opts = append(opts, withCorruptedBlock(1))
			}
			pair := newReactor(t, log.NewNopLogger(), doc, vals, 1, opts...)
			t.Cleanup(func() { require.NoError(t, pair.app.Stop()) })
			lease := &blockLease{}
			policy := &blockPolicy{lease: lease}
			config := cfg.DefaultP2PConfig()
			config.ServingPolicy = policy
			r := pair.reactor.Reactor
			r.SetSwitch(p2p.NewSwitch(config, nil))
			peer := &trackedBlockPeer{blockServingPeer: newBlockServingPeer(t, false), reject: kind == "queue_full"}
			height := int64(1)
			if kind == "missing_block" {
				height = 2
			}
			got := r.respondToPeer(&bc.BlockRequest{Height: height}, peer)
			require.Equal(t, kind == "flushed" || kind == "failed_flush" || kind == "missing_block", got)
			require.Equal(t, []servebudget.Request{{Family: servebudget.Block, Height: uint64(height), MaxBytes: MaxMsgSize}}, policy.requests)
			if peer.done != nil {
				require.Empty(t, lease.results)
				response := peer.message.Message.(*bc.BlockResponse)
				require.Equal(t, int64(1), response.Block.Header.Height)
				require.NotNil(t, response.ExtCommit)
				require.Equal(t, uint64(proto.Size(response.Wrap())), lease.size)
				peer.done(kind == "flushed")
			}
			if kind == "missing_block" {
				require.IsType(t, &bc.NoBlockResponse{}, peer.message.Message)
			}
			require.Equal(t, []bool{kind == "flushed"}, lease.results)
		})
	}
}
