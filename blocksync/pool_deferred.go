package blocksync

import (
	"errors"
	"time"

	"github.com/cometbft/cometbft/p2p"
)

const maxServingDelay = 2 * time.Minute

// DeferRequestFrom grants a bounded wait only for an outstanding request.
func (pool *BlockPool) DeferRequestFrom(height int64, peerID p2p.ID) {
	pool.mtx.Lock()
	defer pool.mtx.Unlock()
	request := pool.requesters[height]
	peer := pool.peers[peerID]
	if request == nil || peer == nil || peer.didTimeout || peer.numPending == 0 {
		return
	}
	until := request.deferFrom(peerID)
	if until.IsZero() || !time.Now().Before(until) {
		return
	}
	if peer.deferrals == nil {
		peer.deferrals = make(map[int64]time.Time)
	}
	peer.deferrals[height] = until
	peer.resetTimeout()
}

func (bpr *bpRequester) deferFrom(peerID p2p.ID) time.Time {
	bpr.mtx.Lock()
	defer bpr.mtx.Unlock()
	if bpr.block != nil || peerID == "" {
		return time.Time{}
	}
	for i, id := range [2]p2p.ID{bpr.peerID, bpr.secondPeerID} {
		if id == peerID && !bpr.requestedAt[i].IsZero() {
			if bpr.deferred[i].IsZero() {
				bpr.deferred[i] = bpr.requestedAt[i].Add(maxServingDelay)
			}
			return bpr.deferred[i]
		}
	}
	return time.Time{}
}

func (pool *BlockPool) deferredRetry(bpr *bpRequester) time.Duration {
	pool.mtx.Lock()
	defer pool.mtx.Unlock()
	bpr.mtx.Lock()
	if bpr.block != nil {
		bpr.mtx.Unlock()
		return requestRetrySeconds * time.Second
	}
	ids, deadlines := [2]p2p.ID{bpr.peerID, bpr.secondPeerID}, bpr.deferred
	bpr.mtx.Unlock()
	wait := time.Duration(0)
	for i, id := range ids {
		if id == "" || deadlines[i].IsZero() || pool.peers[id] == nil {
			continue
		}
		remaining := time.Until(deadlines[i])
		if remaining <= 0 {
			pool.sendError(errors.New("deferred block request timed out"), id)
			pool.removePeer(id)
			remaining = time.Millisecond
		}
		if wait == 0 || remaining < wait {
			wait = remaining
		}
	}
	return wait
}

func (peer *bpPeer) refreshDeferrals() {
	peer.deferredUntil = time.Time{}
	for _, until := range peer.deferrals {
		if until.After(peer.deferredUntil) {
			peer.deferredUntil = until
		}
	}
}

func (peer *bpPeer) clearDeferral(height int64) {
	if _, ok := peer.deferrals[height]; !ok {
		return
	}
	delete(peer.deferrals, height)
	if peer.numPending > 0 {
		peer.resetTimeout()
	} else {
		peer.refreshDeferrals()
	}
}
