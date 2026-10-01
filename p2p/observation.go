package p2p

import "github.com/cometbft/cometbft/p2p/observation"

func (p *peer) observe(event observation.Event) {
	if p.observer != nil {
		p.observer.Observe(string(p.ID()), event)
	}
}

// ObserveInvalid reports an existing peer-attributable protocol validation failure.
// It does not revalidate data, disconnect a peer, or create another jail ledger.
func (sw *Switch) ObserveInvalid(src Peer, channel byte) {
	if sw != nil && sw.config.PeerObserver != nil {
		sw.config.PeerObserver.Observe(string(src.ID()), observation.Event{
			Kind: observation.InvalidMessage, Channel: channel,
		})
	}
}
