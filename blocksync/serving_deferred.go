package blocksync

import (
	"sync"
	"time"

	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/servebudget"
	bc "github.com/cometbft/cometbft/proto/tendermint/blocksync"
)

const (
	maxDeferredPeers = 1024
	// A replacement request can arrive before the worker returns from sending.
	maxDeferredBlocks = maxPendingRequestsPerPeer + 1
)

type deferredBlocks struct {
	mu      sync.Mutex
	wg      sync.WaitGroup
	reactor *Reactor
	policy  servebudget.RetryPolicy
	peers   map[p2p.ID]*deferredPeer
	workers int
	stopped bool
}

type deferredPeer struct {
	peer    p2p.Peer
	heights chan *deferredRequest
	pending map[int64]struct{}
	stop    chan struct{}
}

type deferredRequest struct {
	height int64
	retry  bool
}

func newDeferredBlocks(r *Reactor, policy servebudget.RetryPolicy) *deferredBlocks {
	return &deferredBlocks{reactor: r, policy: policy, peers: make(map[p2p.ID]*deferredPeer)}
}

func (r *Reactor) receiveBlockRequest(msg *bc.BlockRequest, peer p2p.Peer) {
	if r.deferredBlocks == nil {
		r.respondToPeer(msg, peer)
		return
	}
	if allowBlockRequest(r, peer, msg) && !r.deferredBlocks.enqueue(peer, msg.Height) {
		r.metrics.ServingBudgetDrops.Add(1)
	}
}

func (d *deferredBlocks) enqueue(peer p2p.Peer, height int64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped || !peer.IsRunning() {
		return false
	}
	q := d.peers[peer.ID()]
	if q != nil && q.peer != peer {
		return false
	}
	if q == nil {
		if d.workers >= maxDeferredPeers {
			return false
		}
		q = &deferredPeer{peer: peer, heights: make(chan *deferredRequest, maxDeferredBlocks), pending: make(map[int64]struct{}), stop: make(chan struct{})}
		d.peers[peer.ID()] = q
		d.workers++
		d.wg.Add(1)
		go d.run(q)
	}
	if _, ok := q.pending[height]; ok {
		return true
	}
	if len(q.pending) >= maxDeferredBlocks {
		return false
	}
	q.pending[height] = struct{}{}
	q.heights <- &deferredRequest{height: height}
	return true
}

func (d *deferredBlocks) run(q *deferredPeer) {
	defer d.wg.Done()
	defer d.retire(q)
	for {
		select {
		case <-q.stop:
			return
		case <-q.peer.Quit():
			return
		case request := <-q.heights:
			if d.serve(q, request) {
				d.mu.Lock()
				delete(q.pending, request.height)
				d.mu.Unlock()
				continue
			}
			if !d.deferRequest(q, request) {
				return
			}
		}
	}
}

func (d *deferredBlocks) retire(q *deferredPeer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.workers--
	if d.peers[q.peer.ID()] == q {
		delete(d.peers, q.peer.ID())
	}
}

func (d *deferredBlocks) serve(q *deferredPeer, request *deferredRequest) bool {
	select {
	case <-q.stop:
		return true
	case <-q.peer.Quit():
		return true
	default:
	}
	if blockQueueFull(q.peer) {
		return false
	}
	attempt := d.policy.Admit
	if request.retry {
		attempt = d.policy.Retry
	}
	request.retry = true
	req := servebudget.Request{Family: servebudget.Block, Height: uint64(request.height), MaxBytes: MaxMsgSize}
	lease, ok := attempt(string(q.peer.ID()), req)
	if !ok {
		return false
	}
	select {
	case <-q.stop:
		p2p.FinishServing(lease)
	case <-q.peer.Quit():
		p2p.FinishServing(lease)
	default:
		d.reactor.serveBlock(&bc.BlockRequest{Height: request.height}, q.peer, lease)
	}
	return true
}

func (d *deferredBlocks) deferRequest(q *deferredPeer, request *deferredRequest) bool {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-q.stop:
		return false
	case <-q.peer.Quit():
		return false
	case <-timer.C:
	}
	// A denied height must not block other heights that the policy can serve.
	q.heights <- request
	return true
}

func (d *deferredBlocks) remove(peer p2p.Peer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if q := d.peers[peer.ID()]; q != nil && q.peer == peer {
		close(q.stop)
		delete(d.peers, peer.ID())
	}
}

func (d *deferredBlocks) stop() {
	d.mu.Lock()
	d.stopped = true
	for id, q := range d.peers {
		close(q.stop)
		delete(d.peers, id)
	}
	d.mu.Unlock()
	d.wg.Wait()
}
