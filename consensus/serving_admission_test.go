package consensus

import (
	"testing"

	cfgpkg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	"github.com/cometbft/cometbft/types"
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
	require.Nil(t, r.loadCatchupMeta(servingPeer{}, 1))
	require.False(t, r.sendCatchupVote(servingPeer{}, nil, 1, func() types.VoteSetReader { t.Fatal("load before admission"); return nil }))
	require.Positive(t, policy.calls)
}
