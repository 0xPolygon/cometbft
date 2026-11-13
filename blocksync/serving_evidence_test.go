package blocksync

import (
	"errors"
	"testing"

	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	bc "github.com/cometbft/cometbft/proto/tendermint/blocksync"
	"github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

type evidencePolicy struct {
	ids     []string
	reasons []servebudget.Evidence
}

func (*evidencePolicy) Admit(string, servebudget.Request) (servebudget.Lease, bool) { return nil, true }
func (p *evidencePolicy) Observe(id string, reason servebudget.Evidence) {
	p.ids = append(p.ids, id)
	p.reasons = append(p.reasons, reason)
}

func TestServingPoolEvidence(t *testing.T) {
	for _, kind := range []string{"commit_height", "future_height", "before_start", "wrong_peer", "late_response", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			pool := NewBlockPool(10, nil, nil)
			pool.height = 20
			block := &types.Block{Header: types.Header{Height: 15}}
			var commit *types.ExtendedCommit
			switch kind {
			case "commit_height":
				commit = &types.ExtendedCommit{Height: 14}
			case "future_height":
				block.Height = 21
			case "before_start":
				block.Height = 9
			case "wrong_peer":
				req := newBPRequester(pool, 15)
				req.peerID = "different-peer"
				pool.requesters[15] = req
			}
			err := pool.AddBlock(servingPeer{}.ID(), block, commit, 100)
			if kind == "timeout" {
				err = errors.New("peer response timeout")
			}
			require.Error(t, err)
			fault := kind != "late_response" && kind != "timeout"
			var invalid invalidResponseError
			require.Equal(t, fault, errors.As(err, &invalid))
			policy := &evidencePolicy{}
			config := cfg.DefaultP2PConfig()
			config.ServingPolicy = policy
			r := &Reactor{}
			r.BaseReactor = *p2p.NewBaseReactor("test", r)
			r.SetSwitch(p2p.NewSwitch(config, nil))
			r.observePeerError(servingPeer{}, err)
			if fault {
				require.Equal(t, []servebudget.Evidence{servebudget.InvalidResponse}, policy.reasons)
				require.Equal(t, []string{string(servingPeer{}.ID())}, policy.ids)
			} else {
				require.Empty(t, policy.reasons)
			}
		})
	}
}

func TestServingValidationEvidenceClassification(t *testing.T) {
	policy := &evidencePolicy{}
	config := cfg.DefaultP2PConfig()
	config.ServingPolicy = policy
	r := &Reactor{}
	r.BaseReactor = *p2p.NewBaseReactor("test", r)
	r.SetSwitch(p2p.NewSwitch(config, nil))
	r.observeInvalidServing(p2p.Envelope{Src: servingPeer{}, Message: &bc.BlockRequest{Height: -1}})
	r.observeInvalidServing(p2p.Envelope{Src: servingPeer{}, Message: &bc.BlockResponse{}})
	require.Equal(t, []servebudget.Evidence{servebudget.MalformedRequest, servebudget.InvalidResponse}, policy.reasons)
	require.Equal(t, []string{string(servingPeer{}.ID()), string(servingPeer{}.ID())}, policy.ids)
}

func TestServingResponseErrorPreservesCause(t *testing.T) {
	cause := errors.New("invalid peer response")
	pool := NewBlockPool(1, nil, nil)
	err := pool.rejectResponse(cause, servingPeer{}.ID())
	require.ErrorIs(t, err, cause)
	var fault invalidResponseError
	require.ErrorAs(t, err, &fault)
}
