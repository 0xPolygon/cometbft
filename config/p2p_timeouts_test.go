package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/config"
)

func TestP2PTimeoutValidation(t *testing.T) {
	for _, field := range []string{"handshake_timeout", "dial_timeout"} {
		for _, timeout := range []time.Duration{-time.Second, 0, time.Nanosecond, 7 * time.Second} {
			t.Run(field+"/"+timeout.String(), func(t *testing.T) {
				cfg := config.DefaultConfig()
				if field == "handshake_timeout" {
					cfg.P2P.HandshakeTimeout = timeout
				} else {
					cfg.P2P.DialTimeout = timeout
				}
				err := cfg.ValidateBasic()
				if timeout <= 0 {
					require.ErrorContains(t, err, field+" must be positive")
				} else {
					require.NoError(t, err)
				}
			})
		}
	}
}
