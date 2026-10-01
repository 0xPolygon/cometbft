package statesync

import (
	"testing"

	"github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/mocks"
	"github.com/cometbft/cometbft/p2p/observation"
	ss "github.com/cometbft/cometbft/proto/tendermint/statesync"
	"github.com/stretchr/testify/require"
)

type validationObserver struct {
	ids    []string
	events []observation.Event
}

func (o *validationObserver) Observe(id string, e observation.Event) {
	o.ids = append(o.ids, id)
	o.events = append(o.events, e)
}

func TestPeerObservationChunkValidation(t *testing.T) {
	o := &validationObserver{}
	cfg := config.DefaultP2PConfig()
	cfg.PeerObserver = o
	r := NewReactor(*config.DefaultStateSyncConfig(), nil, nil, NopMetrics())
	r.SetSwitch(p2p.NewSwitch(cfg, nil))
	require.NoError(t, r.Start())
	t.Cleanup(func() { require.NoError(t, r.Stop()) })
	peer := &mocks.Peer{}
	peer.On("ID").Return(p2p.ID("peer"))
	peer.On("IsRunning").Return(false)
	r.Receive(p2p.Envelope{Src: peer, ChannelID: ChunkChannel, Message: &ss.ChunkRequest{Height: 0}})
	require.Equal(t, []string{"peer"}, o.ids)
	require.Equal(t, []observation.Event{{Kind: observation.InvalidMessage, Channel: ChunkChannel}}, o.events)
	peer.AssertCalled(t, "IsRunning")
}

func TestPeerObservationLocalSnapshotLimitNeutral(t *testing.T) {
	o := &validationObserver{}
	cfg := config.DefaultP2PConfig()
	cfg.PeerObserver = o
	syncConfig := config.DefaultStateSyncConfig()
	syncConfig.MaxSnapshotChunks = 10
	r := NewReactor(*syncConfig, nil, nil, NopMetrics())
	r.syncer = &syncer{logger: r.Logger, snapshots: newSnapshotPool()}
	r.SetSwitch(p2p.NewSwitch(cfg, nil))
	require.NoError(t, r.Start())
	t.Cleanup(func() { require.NoError(t, r.Stop()) })
	peer := &mocks.Peer{}
	peer.On("ID").Return(p2p.ID("peer"))
	peer.On("IsRunning").Return(false)
	r.Receive(p2p.Envelope{Src: peer, ChannelID: SnapshotChannel, Message: &ss.SnapshotsResponse{Height: 1, Hash: []byte{1}, Chunks: 11}})
	require.Empty(t, o.events)
	peer.AssertCalled(t, "IsRunning")
}
