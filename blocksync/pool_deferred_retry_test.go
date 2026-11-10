package blocksync

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDeferredRetryWithoutNotice(t *testing.T) {
	requests := make(chan BlockRequest, 10)
	errors := make(chan peerError, 10)
	pool := NewBlockPool(1, requests, errors)
	pool.SetPeerRange("peer", 1, 1)
	require.NoError(t, pool.Start())
	t.Cleanup(func() { require.NoError(t, pool.Stop()) })
	keepAlive := time.NewTicker(peerTimeout / 4)
	defer keepAlive.Stop()
	deadline := time.NewTimer(peerConnWait + (requestRetrySeconds+3)*time.Second)
	defer deadline.Stop()
	attempts := 0
	for {
		select {
		case request := <-requests:
			require.Equal(t, int64(1), request.Height)
			attempts++
			if attempts == 2 {
				return
			}
		case <-keepAlive.C:
			// Other traffic can keep a source alive without completing this height.
			pool.mtx.Lock()
			peer := pool.peers["peer"]
			if peer != nil {
				peer.resetTimeout()
			}
			pool.mtx.Unlock()
		case err := <-errors:
			t.Fatalf("source was removed before request retry: %v", err)
		case <-deadline.C:
			t.Fatal("a request without a deferral notice was not retried")
		}
	}
}
