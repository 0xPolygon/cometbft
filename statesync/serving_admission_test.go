package statesync

import (
	"testing"

	cfgpkg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	ss "github.com/cometbft/cometbft/proto/tendermint/statesync"
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
	r := NewReactor(*cfgpkg.DefaultStateSyncConfig(), nil, nil, NopMetrics())
	r.SetSwitch(sw)
	r.serveChunk(p2p.Envelope{Src: servingPeer{}}, &ss.ChunkRequest{Height: 1})
	r.serveSnapshots(p2p.Envelope{Src: servingPeer{}})
	require.Positive(t, policy.calls)
}
