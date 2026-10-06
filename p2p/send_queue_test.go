package p2p

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	cmtconn "github.com/cometbft/cometbft/p2p/conn"
)

func TestPeerSendQueueFull(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	t.Cleanup(func() {
		require.NoError(t, server.Close())
		require.NoError(t, client.Close())
	})
	mconn := cmtconn.NewMConnection(client, []*cmtconn.ChannelDescriptor{{ID: testCh, Priority: 1}}, nil, nil)
	p := &peer{mconn: mconn}
	require.False(t, p.SendQueueFull(testCh))
	require.False(t, p.SendQueueFull(0xff))
	require.NoError(t, mconn.Start())
	var readDone chan struct{}
	t.Cleanup(func() {
		require.NoError(t, mconn.Stop())
		require.NoError(t, server.Close())
		if readDone != nil {
			<-readDone
		}
	})
	require.True(t, mconn.TrySend(testCh, make([]byte, 64<<10)))
	require.True(t, p.SendQueueFull(testCh))
	readDone = make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, server)
		close(readDone)
	}()
	require.Eventually(t, func() bool { return !p.SendQueueFull(testCh) }, time.Second, time.Millisecond)
}
