package config

import (
	"encoding/json"
	"testing"

	"github.com/cometbft/cometbft/p2p/observation"
	"github.com/stretchr/testify/require"
)

type testObserver struct{}

func (*testObserver) Observe(string, observation.Event) {}

func TestPeerObservationConfigIsLocal(t *testing.T) {
	cfg := DefaultP2PConfig()
	require.Nil(t, cfg.PeerObserver)
	cfg.PeerObserver = &testObserver{}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NotContains(t, string(data), "PeerObserver")
	require.NoError(t, json.Unmarshal([]byte(`{"PeerObserver":{"remote":true}}`), cfg))
	require.IsType(t, &testObserver{}, cfg.PeerObserver)
}
