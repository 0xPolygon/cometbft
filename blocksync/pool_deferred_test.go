package blocksync

import (
	"sync"
	"testing"
	"time"

	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

func deferredPool(t *testing.T) (*BlockPool, *bpRequester, *bpPeer) {
	t.Helper()
	pool := NewBlockPool(1, nil, nil)
	pool.SetPeerRange("peer", 1, 100)
	request := newBPRequester(pool, 1)
	request.peerID = "peer"
	request.requestedAt[0] = time.Now()
	pool.requesters[1] = request
	pool.numPending = 1
	peer := pool.peers["peer"]
	peer.incrPending()
	t.Cleanup(func() { pool.RemovePeer(peer.id) })
	return pool, request, peer
}

func TestDeferredRequestCorrelation(t *testing.T) {
	pool, request, peer := deferredPool(t)
	initial := peer.timeoutAt
	pool.DeferRequestFrom(2, peer.id)
	pool.DeferRequestFrom(1, "other")
	require.Equal(t, initial, peer.timeoutAt)
	pool.DeferRequestFrom(1, peer.id)
	until := request.deferred[0]
	require.WithinDuration(t, time.Now().Add(maxServingDelay), until, time.Second)
	require.Equal(t, until, peer.timeoutAt)
	pool.DeferRequestFrom(1, peer.id)
	require.Equal(t, until, request.deferred[0], "repeated notices cannot renew the deadline")
	require.Equal(t, until, peer.timeoutAt)
	require.Greater(t, pool.deferredRetry(request), peerTimeout)
	require.Equal(t, int32(1), peer.numPending)
	require.Equal(t, []p2p.ID{peer.id}, request.requestedFrom())
}

func TestDeferredRequestExpiry(t *testing.T) {
	pool, request, peer := deferredPool(t)
	pool.DeferRequestFrom(1, peer.id)
	request.deferred[0] = time.Now().Add(-time.Second)
	require.Positive(t, pool.deferredRetry(request))
	require.NotContains(t, pool.peers, peer.id)
	require.False(t, pool.IsPeerBanned(peer.id))
	select {
	case id := <-request.redoCh:
		require.Equal(t, peer.id, id)
	default:
		t.Fatal("expired request was not reassigned")
	}
}

func TestDeferredRequestCompletion(t *testing.T) {
	pool, request, peer := deferredPool(t)
	pool.DeferRequestFrom(1, peer.id)
	block := types.MakeBlock(1, nil, &types.Commit{}, nil)
	require.NoError(t, pool.AddBlock(peer.id, block, nil, 1024))
	require.Zero(t, peer.numPending)
	require.True(t, peer.deferredUntil.IsZero())
	pool.DeferRequestFrom(1, peer.id)
	require.True(t, peer.deferredUntil.IsZero())
	peer.onTimeout()
	require.False(t, peer.didTimeout, "stale timer must not reject a completed response")
	require.Equal(t, block, request.getBlock())
}

func TestDeferredRequestStaleTimeout(t *testing.T) {
	pool, _, peer := deferredPool(t)
	pool.DeferRequestFrom(1, peer.id)
	peer.onTimeout()
	require.False(t, peer.didTimeout)
	pool.mtx.Lock()
	peer.timeoutAt = time.Now().Add(-time.Second)
	pool.mtx.Unlock()
	peer.onTimeout()
	require.True(t, peer.didTimeout)
}

func TestDeferredRequestDoesNotProtectOtherPeers(t *testing.T) {
	pool, request, peer := deferredPool(t)
	pool.SetPeerRange("other", 1, 100)
	other := pool.peers["other"]
	other.incrPending()
	t.Cleanup(func() { pool.RemovePeer(other.id) })
	request.secondPeerID = other.id
	request.requestedAt[1] = time.Now()
	deadline := other.timeoutAt
	pool.DeferRequestFrom(1, peer.id)
	require.Equal(t, deadline, other.timeoutAt)
	require.True(t, other.deferredUntil.IsZero())
}

func TestDeferredRequestUsesAssignmentTime(t *testing.T) {
	pool, request, peer := deferredPool(t)
	request.requestedAt[0] = time.Now().Add(-90 * time.Second)
	pool.DeferRequestFrom(1, peer.id)
	require.Equal(t, request.requestedAt[0].Add(maxServingDelay), request.deferred[0])
	require.WithinDuration(t, time.Now().Add(30*time.Second), peer.timeoutAt, time.Second)
}

func TestDeferredExpiredAssignmentIgnored(t *testing.T) {
	pool, request, peer := deferredPool(t)
	initial := peer.timeoutAt
	request.requestedAt[0] = time.Now().Add(-maxServingDelay - time.Second)
	pool.DeferRequestFrom(1, peer.id)
	require.Empty(t, peer.deferrals)
	require.Equal(t, initial, peer.timeoutAt)
	for height := int64(2); height < 1000; height++ {
		pool.DeferRequestFrom(height, peer.id)
	}
	require.Empty(t, peer.deferrals)
	require.Equal(t, initial, peer.timeoutAt)
}

func TestDeferredCompletionRestoresNormalTimeout(t *testing.T) {
	pool, _, peer := deferredPool(t)
	next := newBPRequester(pool, 2)
	next.peerID, next.requestedAt[0] = peer.id, time.Now()
	pool.requesters[2] = next
	pool.numPending++
	peer.incrPending()
	pool.DeferRequestFrom(1, peer.id)
	block := types.MakeBlock(1, nil, &types.Commit{}, nil)
	require.NoError(t, pool.AddBlock(peer.id, block, nil, 1024))
	require.Equal(t, int32(1), peer.numPending)
	require.Empty(t, peer.deferrals)
	require.True(t, peer.deferredUntil.IsZero())
	require.WithinDuration(t, time.Now().Add(peerTimeout), peer.timeoutAt, 100*time.Millisecond)
	deadline := peer.timeoutAt
	pool.DeferRequestFrom(1, peer.id)
	require.Empty(t, peer.deferrals)
	require.Equal(t, deadline, peer.timeoutAt)
}

func TestDeferredMissingBlockRestoresTimeout(t *testing.T) {
	pool, _, peer := deferredPool(t)
	pool.DeferRequestFrom(1, peer.id)
	pool.RedoRequestFrom(1, peer.id)
	require.Empty(t, peer.deferrals)
	require.True(t, peer.deferredUntil.IsZero())
	require.WithinDuration(t, time.Now().Add(peerTimeout), peer.timeoutAt, 100*time.Millisecond)
}

func TestDeferredLowestHeightKeepsDeadline(t *testing.T) {
	pool, first, peer := deferredPool(t)
	second := newBPRequester(pool, 2)
	second.peerID, second.requestedAt[0] = peer.id, time.Now()
	pool.requesters[2] = second
	pool.numPending++
	peer.incrPending()
	pool.DeferRequestFrom(1, peer.id)
	until := first.deferred[0]
	pool.DeferRequestFrom(2, peer.id)
	require.NoError(t, pool.AddBlock(peer.id, types.MakeBlock(2, nil, &types.Commit{}, nil), nil, 1024))
	require.Equal(t, until, first.deferred[0])
	require.Equal(t, until, peer.deferredUntil)
	first.deferred[0] = time.Now().Add(-time.Second)
	require.Positive(t, pool.deferredRetry(first))
	require.NotContains(t, pool.peers, peer.id)
}

func TestDeferredRemovedPeerTimer(t *testing.T) {
	pool, _, peer := deferredPool(t)
	pool.RemovePeer(peer.id)
	pool.SetPeerRange(peer.id, 1, 100)
	peer.timeoutAt = time.Now().Add(-time.Second)
	peer.onTimeout()
	require.False(t, peer.didTimeout)
	require.NotSame(t, peer, pool.peers[peer.id])
}

func TestDeferredResetClearsOnlyMatchingSlot(t *testing.T) {
	pool, request, peer := deferredPool(t)
	request.secondPeerID, request.requestedAt[1] = "other", time.Now()
	pool.DeferRequestFrom(1, peer.id)
	request.deferFrom("other")
	deadline := request.deferred[0]
	request.reset("unknown")
	require.Equal(t, p2p.ID("other"), request.secondPeerID)
	request.reset("other")
	require.True(t, request.deferred[1].IsZero())
	require.True(t, request.requestedAt[1].IsZero())
	require.Equal(t, deadline, request.deferred[0])
	request.reset(peer.id)
	require.True(t, request.deferred[0].IsZero())
	require.True(t, request.requestedAt[0].IsZero())
}

func TestDeferredCompletedRequestKeepsSource(t *testing.T) {
	pool, request, peer := deferredPool(t)
	pool.DeferRequestFrom(1, peer.id)
	require.NoError(t, pool.AddBlock(peer.id, types.MakeBlock(1, nil, &types.Commit{}, nil), nil, 1024))
	request.deferred[0] = time.Now().Add(-time.Second)
	require.Positive(t, pool.deferredRetry(request), "completion notification may race with the retry timer")
	require.Same(t, peer, pool.peers[peer.id])
	require.Zero(t, peer.numPending)
}

func TestDeferredCompletionAndTimerRace(t *testing.T) {
	for range 100 {
		pool, request, peer := deferredPool(t)
		pool.DeferRequestFrom(1, peer.id)
		var wg sync.WaitGroup
		var receivedErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			peer.onTimeout()
			pool.deferredRetry(request)
		}()
		go func() {
			defer wg.Done()
			receivedErr = pool.AddBlock(peer.id, types.MakeBlock(1, nil, &types.Commit{}, nil), nil, 1024)
		}()
		wg.Wait()
		require.NoError(t, receivedErr)
		require.False(t, peer.didTimeout)
		require.Zero(t, peer.numPending)
		require.Empty(t, peer.deferrals)
		pool.RemovePeer(peer.id)
	}
}

func TestDeferredCompletionPreservesOtherSourceDeadline(t *testing.T) {
	pool, request, peer := deferredPool(t)
	pool.SetPeerRange("other", 1, 100)
	other := pool.peers["other"]
	other.incrPending()
	t.Cleanup(func() { pool.RemovePeer(other.id) })
	request.secondPeerID, request.requestedAt[1] = other.id, time.Now()
	deadline := other.timeoutAt
	require.NoError(t, pool.AddBlock(peer.id, types.MakeBlock(1, nil, &types.Commit{}, nil), nil, 1024))
	require.Equal(t, deadline, other.timeoutAt, "another peer's response must not renew this source's timeout")
}

func TestDeferredStaleCallbackRearmsTimer(t *testing.T) {
	pool, _, peer := deferredPool(t)
	pool.mtx.Lock()
	peer.timeout.Stop()
	peer.timeoutAt = time.Now().Add(100 * time.Millisecond)
	pool.mtx.Unlock()
	peer.onTimeout()
	require.Eventually(t, func() bool {
		pool.mtx.Lock()
		defer pool.mtx.Unlock()
		return peer.didTimeout
	}, time.Second, time.Millisecond)
}

func TestDeferredTimerReturnsToNormalDeadline(t *testing.T) {
	pool, _, peer := deferredPool(t)
	pool.mtx.Lock()
	peer.timeout.Reset(time.Hour)
	peer.resetTimeout()
	pool.mtx.Unlock()
	require.Eventually(t, func() bool {
		pool.mtx.Lock()
		defer pool.mtx.Unlock()
		return peer.didTimeout
	}, peerTimeout+time.Second, time.Millisecond)
}
