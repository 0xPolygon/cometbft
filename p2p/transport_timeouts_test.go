package p2p

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/ed25519"
)

func TestTransportTimeoutOptions(t *testing.T) {
	mt := newMultiplexTransport(emptyNodeInfo(), NodeKey{PrivKey: ed25519.GenPrivKey()})
	require.Equal(t, time.Second, mt.dialTimeout)
	require.Equal(t, 3*time.Second, mt.handshakeTimeout)

	MultiplexTransportDialTimeout(7 * time.Second)(mt)
	require.Equal(t, 7*time.Second, mt.dialTimeout)
	require.Equal(t, 3*time.Second, mt.handshakeTimeout)

	MultiplexTransportHandshakeTimeout(11 * time.Second)(mt)
	require.Equal(t, 7*time.Second, mt.dialTimeout)
	require.Equal(t, 11*time.Second, mt.handshakeTimeout)
	require.Equal(t, 5*time.Second, mt.filterTimeout)
}

func TestTransportConfiguredHandshakeDeadline(t *testing.T) {
	mt := newMultiplexTransport(emptyNodeInfo(), NodeKey{PrivKey: ed25519.GenPrivKey()})
	MultiplexTransportHandshakeTimeout(50 * time.Millisecond)(mt)
	local, remote := net.Pipe()
	t.Cleanup(func() { require.NoError(t, local.Close()) })
	t.Cleanup(func() { require.NoError(t, remote.Close()) })

	started := time.Now()
	_, _, err := mt.upgrade(local, nil)
	require.ErrorContains(t, err, "i/o timeout")
	require.GreaterOrEqual(t, time.Since(started), mt.handshakeTimeout)
	require.Less(t, time.Since(started), time.Second)
}
