package p2p

import (
	"sync"

	"github.com/cometbft/cometbft/p2p/servebudget"
	"github.com/cosmos/gogoproto/proto"
)

func (sw *Switch) ServingPolicy() servebudget.Policy {
	if sw == nil {
		return nil
	}
	return sw.config.ServingPolicy
}

func (sw *Switch) AdmitServing(src Peer, req servebudget.Request) (servebudget.Lease, bool) {
	if policy := sw.ServingPolicy(); policy != nil {
		return policy.Admit(string(src.ID()), req)
	}
	return nil, true
}

func (sw *Switch) ObserveServing(src Peer, evidence servebudget.Evidence) {
	if policy := sw.ServingPolicy(); policy != nil {
		policy.Observe(string(src.ID()), evidence)
	}
}

func FinishServing(lease servebudget.Lease) {
	if lease != nil {
		lease.Finish(false)
	}
}

// SendServing transfers the lease to the connection writer, including batches of
// snapshot descriptors. No completion credit is given until every frame is flushed.
func SendServing(src Peer, lease servebudget.Lease, messages ...Envelope) bool {
	if lease == nil {
		for _, e := range messages {
			if !src.TrySend(e) {
				return false
			}
		}
		return true
	}
	tracked, ok := src.(trackedSender)
	if !ok || len(messages) == 0 {
		lease.Finish(false)
		return false
	}
	size := servingSize(messages)
	if !lease.Prepare(size) {
		lease.Finish(false)
		return false
	}
	return sendServingBatch(tracked, lease, messages)
}

type trackedSender interface {
	TrySendTracked(Envelope, func(bool)) bool
}

func servingSize(messages []Envelope) uint64 {
	var size uint64
	for _, e := range messages {
		msg := e.Message
		if w, ok := msg.(Wrapper); ok {
			msg = w.Wrap()
		}
		size += uint64(proto.Size(msg))
	}
	return size
}

func sendServingBatch(tracked trackedSender, lease servebudget.Lease, messages []Envelope) bool {
	batch := &servingBatch{remaining: len(messages), lease: lease, success: true}
	for i, e := range messages {
		if !tracked.TrySendTracked(e, batch.complete) {
			for range messages[i:] {
				batch.complete(false)
			}
			return false
		}
	}
	return true
}

type servingBatch struct {
	mu        sync.Mutex
	remaining int
	success   bool
	lease     servebudget.Lease
}

func (b *servingBatch) complete(written bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.remaining--
	b.success = b.success && written
	if b.remaining == 0 {
		b.lease.Finish(b.success)
	}
}
