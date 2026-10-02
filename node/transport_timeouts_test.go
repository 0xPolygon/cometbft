package node

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/p2p"
)

func TestCreateTransportTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		dial      time.Duration
		handshake time.Duration
	}{
		{"config defaults", 3 * time.Second, 20 * time.Second},
		{"custom", 7 * time.Second, 11 * time.Second},
		{"legacy transport", time.Second, 3 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			if tc.name != "config defaults" {
				cfg.P2P.DialTimeout = tc.dial
				cfg.P2P.HandshakeTimeout = tc.handshake
			}
			key := &p2p.NodeKey{PrivKey: ed25519.GenPrivKey()}
			transport, _ := createTransport(cfg, p2p.DefaultNodeInfo{}, key, nil)
			t.Cleanup(func() { require.NoError(t, transport.Close()) })

			// Inspect wiring without adding a production getter for test-only state.
			state := reflect.ValueOf(transport).Elem()
			require.Equal(t, int64(tc.dial), state.FieldByName("dialTimeout").Int())
			require.Equal(t, int64(tc.handshake), state.FieldByName("handshakeTimeout").Int())
			require.Equal(t, int64(5*time.Second), state.FieldByName("filterTimeout").Int())
		})
	}
}
