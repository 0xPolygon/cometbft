package blocksync

import (
	"testing"

	cfgpkg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	bc "github.com/cometbft/cometbft/proto/tendermint/blocksync"
	"github.com/stretchr/testify/require"
)

type deniedPolicy struct{ calls int }

func (p *deniedPolicy) Admit(string, servebudget.Request) (servebudget.Lease, bool) {
	p.calls++
	return nil, false
}
func (*deniedPolicy) Observe(string, servebudget.Evidence) {}

type servingPeer struct{ p2p.Peer }

func (servingPeer) ID() p2p.ID { return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
func TestNativeServingBeforeLoad(t *testing.T) {
	cfg := cfgpkg.DefaultP2PConfig()
	policy := &deniedPolicy{}
	cfg.ServingPolicy = policy
	sw := p2p.NewSwitch(cfg, nil)
	r := &Reactor{}
	r.BaseReactor = *p2p.NewBaseReactor("test", r)
	r.SetSwitch(sw)
	require.False(t, r.respondToPeer(&bc.BlockRequest{Height: 1}, servingPeer{}))
	require.Positive(t, policy.calls)
}
