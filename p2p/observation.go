package p2p

import "github.com/cometbft/cometbft/p2p/observation"

func (p *peer) observe(event observation.Event) bool {
	if p.observer != nil {
		p.observer.Observe(string(p.ID()), event)
	}
	return p.allowConnection()
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

func (p *peer) allowConnection() bool {
	if p.policy == nil || p.policy.AllowPeer(string(p.ID())) {
		return true
	}
	p.policyClose.Do(func() {
		p.Logger.Info("Closing peer connection by policy", "peer", p.ID())
		// Wake the existing connection error path, which removes the peer from
		// reactors and retains native persistent-peer reconnect handling.
		if err := p.CloseConn(); err != nil {
			p.Logger.Debug("Closing peer connection", "err", err)
		}
	})
	return false
}
