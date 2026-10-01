package blocksync

import (
	"github.com/go-kit/kit/metrics"

	"github.com/cometbft/cometbft/p2p"
)

// WithSendQueueFullDrops records requests rejected by the send queue guard.
func WithSendQueueFullDrops(counter metrics.Counter) ReactorOption {
	return func(r *Reactor) {
		if counter != nil {
			r.sendQueueFullDrops = counter
		}
	}
}

func blockQueueFull(peer p2p.Peer) bool {
	queue, ok := peer.(interface{ SendQueueFull(byte) bool })
	return ok && queue.SendQueueFull(BlocksyncChannel)
}
