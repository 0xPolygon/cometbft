package p2p

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/cosmos/gogoproto/proto"

	"github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/libs/cmap"
	"github.com/cometbft/cometbft/libs/rand"
	"github.com/cometbft/cometbft/libs/service"
	cmtsync "github.com/cometbft/cometbft/libs/sync"
	"github.com/cometbft/cometbft/p2p/conn"
)

const (
	// wait a random amount of time from this interval
	// before dialing peers or reconnecting to help prevent DoS
	dialRandomizerIntervalMilliseconds = 3000

	// the most randomSleep can add on top of the interval it is given
	maxDialRandomizerInterval = dialRandomizerIntervalMilliseconds * time.Millisecond

	// repeatedly try to reconnect for a few minutes
	// ie. 5 * 20 = 100s
	reconnectAttempts = 20
	reconnectInterval = 5 * time.Second

	// then move into exponential backoff mode for ~1day
	// ie. 3**10 = 16hrs
	reconnectBackOffAttempts    = 10
	reconnectBackOffBaseSeconds = 3

	// once backoff is exhausted, a peer that is still configured as persistent
	// is redialed at this interval indefinitely. PEX cannot be relied on to
	// restore the link: ensurePeers only dials when there is outbound headroom
	// and picks from the addrbook at random, so a configured peer can stay
	// unconnected until the node is restarted.
	reconnectPersistentInterval = 10 * time.Minute
)

// MConnConfig returns an MConnConfig with fields updated
// from the P2PConfig.
func MConnConfig(cfg *config.P2PConfig) conn.MConnConfig {
	mConfig := conn.DefaultMConnConfig()
	mConfig.FlushThrottle = cfg.FlushThrottleTimeout
	mConfig.SendRate = cfg.SendRate
	mConfig.RecvRate = cfg.RecvRate
	mConfig.MaxPacketMsgPayloadSize = cfg.MaxPacketMsgPayloadSize
	mConfig.TestFuzz = cfg.TestFuzz
	mConfig.TestFuzzConfig = cfg.TestFuzzConfig
	return mConfig
}

//-----------------------------------------------------------------------------

// An AddrBook represents an address book from the pex package, which is used
// to store peer addresses.
type AddrBook interface {
	AddAddress(addr *NetAddress, src *NetAddress) error
	AddPrivateIDs([]string)
	AddOurAddress(*NetAddress)
	OurAddress(*NetAddress) bool
	MarkGood(ID)
	RemoveAddress(*NetAddress)
	HasAddress(*NetAddress) bool
	Save()
}

// PeerFilterFunc to be implemented by filter hooks after a new Peer has been
// fully setup.
type PeerFilterFunc func(IPeerSet, Peer) error

//-----------------------------------------------------------------------------

// Switch handles peer connections and exposes an API to receive incoming messages
// on `Reactors`.  Each `Reactor` is responsible for handling incoming messages of one
// or more `Channels`.  So while sending outgoing messages is typically performed on the peer,
// incoming messages are received on the reactor.
type Switch struct {
	service.BaseService

	config        *config.P2PConfig
	reactors      map[string]Reactor
	chDescs       []*conn.ChannelDescriptor
	reactorsByCh  map[byte]Reactor
	msgTypeByChID map[byte]proto.Message
	peers         *PeerSet
	dialing       *cmap.CMap
	reconnecting  *cmap.CMap
	nodeInfo      NodeInfo // our node info
	nodeKey       *NodeKey // our node privkey
	addrBook      AddrBook
	// operator-configured peer sets: addresses we maintain a constant
	// connection to, and ids exempt from the peer limits. Both are guarded by
	// peerCfgMtx because unsafe_dial_peers mutates them at runtime while the
	// reconnect, accept and pex paths read them.
	peerCfgMtx           cmtsync.RWMutex
	persistentPeersAddrs []*NetAddress
	unconditionalPeerIDs map[ID]struct{}

	transport Transport

	filterTimeout time.Duration
	peerFilters   []PeerFilterFunc

	rng *rand.Rand // seed for randomizing dial times and orders

	metrics *Metrics
	mlc     *metricsLabelCache
}

// NetAddress returns the address the switch is listening on.
func (sw *Switch) NetAddress() *NetAddress {
	addr := sw.transport.NetAddress()
	return &addr
}

// SwitchOption sets an optional parameter on the Switch.
type SwitchOption func(*Switch)

// NewSwitch creates a new Switch with the given config.
func NewSwitch(
	cfg *config.P2PConfig,
	transport Transport,
	options ...SwitchOption,
) *Switch {

	sw := &Switch{
		config:               cfg,
		reactors:             make(map[string]Reactor),
		chDescs:              make([]*conn.ChannelDescriptor, 0),
		reactorsByCh:         make(map[byte]Reactor),
		msgTypeByChID:        make(map[byte]proto.Message),
		peers:                NewPeerSet(),
		dialing:              cmap.NewCMap(),
		reconnecting:         cmap.NewCMap(),
		metrics:              NopMetrics(),
		transport:            transport,
		filterTimeout:        defaultFilterTimeout,
		persistentPeersAddrs: make([]*NetAddress, 0),
		unconditionalPeerIDs: make(map[ID]struct{}),
		mlc:                  newMetricsLabelCache(),
	}

	// Ensure we have a completely undeterministic PRNG.
	sw.rng = rand.NewRand()

	sw.BaseService = *service.NewBaseService(nil, "P2P Switch", sw)

	for _, option := range options {
		option(sw)
	}

	return sw
}

// SwitchFilterTimeout sets the timeout used for peer filters.
func SwitchFilterTimeout(timeout time.Duration) SwitchOption {
	return func(sw *Switch) { sw.filterTimeout = timeout }
}

// SwitchPeerFilters sets the filters for rejection of new peers.
func SwitchPeerFilters(filters ...PeerFilterFunc) SwitchOption {
	return func(sw *Switch) { sw.peerFilters = filters }
}

// WithMetrics sets the metrics.
func WithMetrics(metrics *Metrics) SwitchOption {
	return func(sw *Switch) { sw.metrics = metrics }
}

//---------------------------------------------------------------------
// Switch setup

// AddReactor adds the given reactor to the switch.
// NOTE: Not goroutine safe.
func (sw *Switch) AddReactor(name string, reactor Reactor) Reactor {
	for _, chDesc := range reactor.GetChannels() {
		chID := chDesc.ID
		// No two reactors can share the same channel.
		if sw.reactorsByCh[chID] != nil {
			panic(fmt.Sprintf("Channel %X has multiple reactors %v & %v", chID, sw.reactorsByCh[chID], reactor))
		}
		sw.chDescs = append(sw.chDescs, chDesc)
		sw.reactorsByCh[chID] = reactor
		sw.msgTypeByChID[chID] = chDesc.MessageType
	}
	sw.reactors[name] = reactor
	reactor.SetSwitch(sw)
	return reactor
}

// RemoveReactor removes the given Reactor from the Switch.
// NOTE: Not goroutine safe.
func (sw *Switch) RemoveReactor(name string, reactor Reactor) {
	for _, chDesc := range reactor.GetChannels() {
		// remove channel description
		for i := 0; i < len(sw.chDescs); i++ {
			if chDesc.ID == sw.chDescs[i].ID {
				sw.chDescs = append(sw.chDescs[:i], sw.chDescs[i+1:]...)
				break
			}
		}
		delete(sw.reactorsByCh, chDesc.ID)
		delete(sw.msgTypeByChID, chDesc.ID)
	}
	delete(sw.reactors, name)
	reactor.SetSwitch(nil)
}

// Reactors returns a map of reactors registered on the switch.
// NOTE: Not goroutine safe.
func (sw *Switch) Reactors() map[string]Reactor {
	return sw.reactors
}

// Reactor returns the reactor with the given name.
// NOTE: Not goroutine safe.
func (sw *Switch) Reactor(name string) Reactor {
	return sw.reactors[name]
}

// SetNodeInfo sets the switch's NodeInfo for checking compatibility and handshaking with other nodes.
// NOTE: Not goroutine safe.
func (sw *Switch) SetNodeInfo(nodeInfo NodeInfo) {
	sw.nodeInfo = nodeInfo
}

// NodeInfo returns the switch's NodeInfo.
// NOTE: Not goroutine safe.
func (sw *Switch) NodeInfo() NodeInfo {
	return sw.nodeInfo
}

// SetNodeKey sets the switch's private key for authenticated encryption.
// NOTE: Not goroutine safe.
func (sw *Switch) SetNodeKey(nodeKey *NodeKey) {
	sw.nodeKey = nodeKey
}

//---------------------------------------------------------------------
// Service start/stop

// OnStart implements BaseService. It starts all the reactors and peers.
func (sw *Switch) OnStart() error {
	// Start reactors
	for _, reactor := range sw.reactors {
		err := reactor.Start()
		if err != nil {
			return fmt.Errorf("failed to start %v: %w", reactor, err)
		}
	}

	// Start accepting Peers.
	go sw.acceptRoutine()

	return nil
}

// OnStop implements BaseService. It stops all peers and reactors.
func (sw *Switch) OnStop() {
	// Stop peers
	for _, p := range sw.peers.List() {
		sw.stopAndRemovePeer(p, nil)
	}

	// Stop reactors
	sw.Logger.Debug("Switch: Stopping reactors")
	for _, reactor := range sw.reactors {
		if err := reactor.Stop(); err != nil {
			sw.Logger.Error("error while stopped reactor", "reactor", reactor, "error", err)
		}
	}
}

//---------------------------------------------------------------------
// Peers

// Broadcast runs a go routine for each attempted send, which will block trying
// to send for defaultSendTimeoutSeconds. Returns a channel which receives
// success values for each attempted send (false if times out). Channel will be
// closed once msg bytes are sent to all peers (or time out).
//
// NOTE: Broadcast uses goroutines, so order of broadcast may not be preserved.
func (sw *Switch) Broadcast(e Envelope) chan bool {
	sw.Logger.Debug("Broadcast", "channel", e.ChannelID)

	peers := sw.peers.List()
	var wg sync.WaitGroup
	wg.Add(len(peers))
	successChan := make(chan bool, len(peers))

	for _, peer := range peers {
		go func(p Peer) {
			defer wg.Done()
			success := p.Send(e)
			successChan <- success
		}(peer)
	}

	go func() {
		wg.Wait()
		close(successChan)
	}()

	return successChan
}

// NumPeers returns the count of outbound/inbound and outbound-dialing peers.
// unconditional peers are not counted here.
func (sw *Switch) NumPeers() (outbound, inbound, dialing int) {
	peers := sw.peers.List()
	for _, peer := range peers {
		if peer.IsOutbound() {
			if !sw.IsPeerUnconditional(peer.ID()) {
				outbound++
			}
		} else {
			if !sw.IsPeerUnconditional(peer.ID()) {
				inbound++
			}
		}
	}
	dialing = sw.dialing.Size()
	return
}

func (sw *Switch) IsPeerUnconditional(id ID) bool {
	sw.peerCfgMtx.RLock()
	defer sw.peerCfgMtx.RUnlock()

	_, ok := sw.unconditionalPeerIDs[id]
	return ok
}

// MaxNumOutboundPeers returns a maximum number of outbound peers.
func (sw *Switch) MaxNumOutboundPeers() int {
	return sw.config.MaxNumOutboundPeers
}

// Peers returns the set of peers that are connected to the switch.
func (sw *Switch) Peers() IPeerSet {
	return sw.peers
}

// StopPeerForError disconnects from a peer due to external error.
// If the peer is persistent, it will attempt to reconnect.
// TODO: make record depending on reason.
func (sw *Switch) StopPeerForError(peer Peer, reason interface{}) {
	if !peer.IsRunning() {
		return
	}

	sw.Logger.Error("Stopping peer for error", "peer", peer, "err", reason)
	sw.stopAndRemovePeer(peer, reason)

	if peer.IsPersistent() {
		var addr *NetAddress
		if peer.IsOutbound() { // socket address for outbound peers
			addr = peer.SocketAddr()
		} else { // self-reported address for inbound peers
			var err error
			addr, err = peer.NodeInfo().NetAddress()
			if err != nil {
				sw.Logger.Error("Wanted to reconnect to inbound peer, but self-reported address is wrong",
					"peer", peer, "err", err)
				return
			}
		}
		go sw.reconnectToPeer(addr)
	}
}

// StopPeerGracefully disconnects from a peer gracefully.
// TODO: handle graceful disconnects.
func (sw *Switch) StopPeerGracefully(peer Peer) {
	sw.Logger.Info("Stopping peer gracefully")
	sw.stopAndRemovePeer(peer, nil)
}

func (sw *Switch) stopAndRemovePeer(peer Peer, reason interface{}) {
	sw.transport.Cleanup(peer)
	if err := peer.Stop(); err != nil {
		sw.Logger.Error("error while stopping peer", "error", err) // TODO: should return error to be handled accordingly
	}

	for _, reactor := range sw.reactors {
		reactor.RemovePeer(peer, reason)
	}

	// Removing a peer should go last to avoid a situation where a peer
	// reconnect to our node and the switch calls InitPeer before
	// RemovePeer is finished.
	// https://github.com/tendermint/tendermint/issues/3338
	if sw.peers.Remove(peer) {
		sw.metrics.Peers.Add(float64(-1))
	} else {
		// Removal of the peer has failed. The function above sets a flag within the peer to mark this.
		// We keep this message here as information to the developer.
		sw.Logger.Debug("error on peer removal", ",", "peer", peer.ID())
	}
}

// dialForReconnect dials addr once and reports whether the reconnect loop is
// done, either because the peer is back or because retrying is pointless.
// NOTE: this will keep trying even if the handshake or auth fails.
// TODO: be more explicit with error types so we only retry on certain failures
//   - ie. if we're getting ErrDuplicatePeer we can stop
//     because the addrbook got us the peer back already
func (sw *Switch) dialForReconnect(addr *NetAddress, tries int) bool {
	if !sw.IsRunning() {
		return true
	}

	err := sw.DialPeerWithAddress(addr)
	if err == nil {
		return true // success
	} else if _, ok := err.(ErrCurrentlyDialingOrExistingAddress); ok {
		return true
	}

	sw.Logger.Info("Error reconnecting to peer. Trying again", "tries", tries, "err", err, "addr", addr)
	return false
}

// reconnectPolicy is the retry schedule reconnectToPeer follows. It is a
// parameter so tests can drive the whole schedule, including what happens once
// backoff is exhausted, without waiting out the production timings.
type reconnectPolicy struct {
	attempts        int
	interval        time.Duration
	backOffAttempts int
	backOffBase     float64
	persistentEvery time.Duration
}

func (sw *Switch) defaultReconnectPolicy() reconnectPolicy {
	return reconnectPolicy{
		attempts:        reconnectAttempts,
		interval:        reconnectInterval,
		backOffAttempts: reconnectBackOffAttempts,
		backOffBase:     reconnectBackOffBaseSeconds,
		persistentEvery: sw.persistentRedialInterval(),
	}
}

// persistentRedialInterval is how often a configured persistent peer is
// redialed once backoff is exhausted. PersistentPeersMaxDialPeriod is the
// operator's existing knob for bounding how slowly a persistent peer gets
// redialed, so honor it rather than adding a second one. It caps the pause, so
// it can only shorten the default; it defaults to 0, meaning unset. It is
// floored at reconnectInterval so that a very small value cannot turn this into
// a dial loop holding an outbound slot that PEX counts as in use.
//
// randomSleep adds up to maxDialRandomizerInterval of jitter on top, so that
// much is subtracted here: the configured value is a maximum pause, and the
// sleep it produces has to stay under it.
func (sw *Switch) persistentRedialInterval() time.Duration {
	capped := reconnectPersistentInterval
	if d := sw.config.PersistentPeersMaxDialPeriod; d > 0 && d < capped {
		capped = d
	}
	if capped < reconnectInterval {
		capped = reconnectInterval
	}

	if capped > maxDialRandomizerInterval {
		return capped - maxDialRandomizerInterval
	}
	return 0
}

// reconnectToPeer tries to reconnect to the addr, first repeatedly
// with a fixed interval (approximately 2 minutes), then with
// exponential backoff (approximately close to 24 hours).
// A peer that is still configured as persistent once backoff is exhausted is
// then redialed at reconnectPersistentInterval for as long as the switch runs,
// because nothing else in the stack is guaranteed to restore that link.
// Any other addr is left to the PEX/Addrbook to find again.
func (sw *Switch) reconnectToPeer(addr *NetAddress) {
	sw.reconnectToPeerWithPolicy(addr, sw.defaultReconnectPolicy())
}

// dialAtFixedInterval runs the fixed-interval phase of the schedule and reports
// whether the reconnect is finished.
func (sw *Switch) dialAtFixedInterval(addr *NetAddress, policy reconnectPolicy) bool {
	for i := 0; i < policy.attempts; i++ {
		if sw.dialForReconnect(addr, i) {
			return true
		}
		// sleep a set amount
		if !sw.randomSleep(policy.interval) {
			return true
		}
	}
	return false
}

// dialWithBackOff runs the exponential-backoff phase of the schedule and
// reports whether the reconnect is finished.
func (sw *Switch) dialWithBackOff(addr *NetAddress, policy reconnectPolicy) bool {
	for i := 1; i <= policy.backOffAttempts; i++ {
		// sleep an exponentially increasing amount
		sleepIntervalSeconds := math.Pow(policy.backOffBase, float64(i))
		if !sw.randomSleep(time.Duration(sleepIntervalSeconds) * time.Second) {
			return true
		}

		if sw.dialForReconnect(addr, i) {
			return true
		}
	}
	return false
}

func (sw *Switch) reconnectToPeerWithPolicy(addr *NetAddress, policy reconnectPolicy) {
	if sw.reconnecting.Has(string(addr.ID)) {
		return
	}
	sw.reconnecting.Set(string(addr.ID), addr)
	defer sw.reconnecting.Delete(string(addr.ID))

	start := time.Now()
	sw.Logger.Info("Reconnecting to peer", "addr", addr)

	if sw.dialAtFixedInterval(addr, policy) {
		return
	}

	sw.Logger.Error("Failed to reconnect to peer. Beginning exponential backoff",
		"addr", addr, "elapsed", time.Since(start))

	if sw.dialWithBackOff(addr, policy) {
		return
	}

	if !sw.IsPeerPersistent(addr) {
		sw.Logger.Error("Failed to reconnect to peer. Giving up", "addr", addr, "elapsed", time.Since(start))
		return
	}

	sw.Logger.Error("Failed to reconnect to persistent peer. Retrying at a fixed interval",
		"addr", addr, "elapsed", time.Since(start), "interval", policy.persistentEvery)
	sw.keepDialingPersistentPeer(addr, policy.persistentEvery)
}

// isTerminalDialErr reports whether retrying the dial is pointless. Only our
// own address qualifies: the switch has already moved it to ourAddrs, so no
// amount of retrying can connect it. An authentication failure deliberately
// does not qualify, since a peer can serve an unexpected key temporarily while
// being upgraded, and giving up on it would reintroduce the dropped link.
func isTerminalDialErr(err error) bool {
	var rejected ErrRejected
	if errors.As(err, &rejected) {
		return rejected.IsSelf()
	}
	return false
}

// keepDialingPersistentPeer redials addr every interval for as long as it stays
// configured as persistent and the switch is running. Unlike the bounded phases
// of reconnectToPeer it never abandons the address: the operator asked for a
// constant connection, and nothing else in the stack reliably re-establishes
// it. PEX only dials when there is spare outbound capacity and then picks from
// the addrbook at random, so a dropped persistent peer can otherwise stay
// unconnected until the node restarts.
//
// Persistence is re-read after every sleep, so removing the address from the
// configured set (AddPersistentPeers, which replaces the set rather than
// extending it) is what stops this loop short of a successful dial. The check
// has to happen after waking rather than only before sleeping, otherwise an
// address removed mid-sleep still gets one more dial and could be reconnected
// behind the operator's back.
func (sw *Switch) keepDialingPersistentPeer(addr *NetAddress, interval time.Duration) {
	for i := 1; sw.IsPeerPersistent(addr); i++ {
		if !sw.randomSleep(interval) {
			return
		}
		if !sw.IsPeerPersistent(addr) {
			break
		}

		if sw.dialPersistentPeer(addr, i) {
			return
		}
	}
	sw.Logger.Info("Peer is no longer persistent. Stopped reconnecting", "addr", addr)
}

// dialPersistentPeer dials addr once and reports whether the persistent phase
// is over, which only a live peer or an undialable address can decide.
// dialForReconnect is deliberately not reused here: it also reports done for
// ErrCurrentlyDialingOrExistingAddress, which a concurrent PEX dial or an
// unrelated peer holding the same IP can trigger while this address is still
// unconnected, and treating that as success would abandon the address for good
func (sw *Switch) dialPersistentPeer(addr *NetAddress, tries int) bool {
	if sw.peers.Has(addr.ID) {
		sw.Logger.Info("Persistent peer is connected again. Stopped reconnecting",
			"addr", addr, "tries", tries)
		return true
	}

	err := sw.DialPeerWithAddress(addr)
	if err == nil {
		sw.Logger.Info("Reconnected to persistent peer", "addr", addr, "tries", tries)
		return true
	}
	if isTerminalDialErr(err) {
		sw.Logger.Error("Persistent peer cannot be dialed. Giving up",
			"addr", addr, "err", err, "tries", tries)
		return true
	}

	sw.Logger.Info("Error reconnecting to persistent peer. Trying again",
		"tries", tries, "err", err, "addr", addr)
	return false
}

// SetAddrBook allows to set address book on Switch.
func (sw *Switch) SetAddrBook(addrBook AddrBook) {
	sw.addrBook = addrBook
}

// MarkPeerAsGood marks the given peer as good when it did something useful
// like contributed to consensus.
func (sw *Switch) MarkPeerAsGood(peer Peer) {
	if sw.addrBook != nil {
		sw.addrBook.MarkGood(peer.ID())
	}
}

//---------------------------------------------------------------------
// Dialing

type privateAddr interface {
	PrivateAddr() bool
}

func isPrivateAddr(err error) bool {
	te, ok := err.(privateAddr)
	return ok && te.PrivateAddr()
}

// DialPeersAsync dials a list of peers asynchronously in random order.
// Used to dial peers from config on startup or from unsafe-RPC (trusted sources).
// It ignores ErrNetAddressLookup. However, if there are other errors, first
// encounter is returned.
// Nop if there are no peers.
func (sw *Switch) DialPeersAsync(peers []string) error {
	netAddrs, errs := NewNetAddressStrings(peers)
	// report all the errors
	for _, err := range errs {
		sw.Logger.Error("Error in peer's address", "err", err)
	}
	// return first non-ErrNetAddressLookup error
	for _, err := range errs {
		if _, ok := err.(ErrNetAddressLookup); ok {
			continue
		}
		return err
	}
	sw.dialPeersAsync(netAddrs)
	return nil
}

func (sw *Switch) dialPeersAsync(netAddrs []*NetAddress) {
	ourAddr := sw.NetAddress()

	// TODO: this code feels like it's in the wrong place.
	// The integration tests depend on the addrBook being saved
	// right away but maybe we can change that. Recall that
	// the addrBook is only written to disk every 2min
	if sw.addrBook != nil {
		// add peers to `addrBook`
		for _, netAddr := range netAddrs {
			// do not add our address or ID
			if !netAddr.Same(ourAddr) {
				if err := sw.addrBook.AddAddress(netAddr, ourAddr); err != nil {
					if isPrivateAddr(err) {
						sw.Logger.Debug("Won't add peer's address to addrbook", "err", err)
					} else {
						sw.Logger.Error("Can't add peer's address to addrbook", "err", err)
					}
				}
			}
		}
		// Persist some peers to disk right away.
		// NOTE: integration tests depend on this
		sw.addrBook.Save()
	}

	// permute the list, dial them in random order.
	perm := sw.rng.Perm(len(netAddrs))
	for i := 0; i < len(perm); i++ {
		go func(i int) {
			j := perm[i]
			addr := netAddrs[j]

			if addr.Same(ourAddr) {
				sw.Logger.Debug("Ignore attempt to connect to ourselves", "addr", addr, "ourAddr", ourAddr)
				return
			}

			if !sw.randomSleep(0) {
				return
			}

			err := sw.DialPeerWithAddress(addr)
			if err != nil {
				switch err.(type) {
				case ErrSwitchConnectToSelf, ErrSwitchDuplicatePeerID, ErrCurrentlyDialingOrExistingAddress:
					sw.Logger.Debug("Error dialing peer", "err", err)
				default:
					sw.Logger.Error("Error dialing peer", "err", err)
				}
			}
		}(i)
	}
}

// DialPeerWithAddress dials the given peer and runs sw.addPeer if it connects
// and authenticates successfully.
// If we're currently dialing this address or it belongs to an existing peer,
// ErrCurrentlyDialingOrExistingAddress is returned.
func (sw *Switch) DialPeerWithAddress(addr *NetAddress) error {
	if sw.IsDialingOrExistingAddress(addr) {
		return ErrCurrentlyDialingOrExistingAddress{addr.String()}
	}

	sw.dialing.Set(string(addr.ID), addr)
	defer sw.dialing.Delete(string(addr.ID))

	return sw.addOutboundPeerWithConfig(addr, sw.config)
}

// sleep for interval plus some random amount of ms on [0, dialRandomizerIntervalMilliseconds].
// It reports false if the switch stopped before the interval elapsed, so callers
// that sleep in a loop terminate on shutdown instead of outliving the switch.
func (sw *Switch) randomSleep(interval time.Duration) bool {
	r := time.Duration(sw.rng.Int63n(dialRandomizerIntervalMilliseconds)) * time.Millisecond
	timer := time.NewTimer(r + interval)
	defer timer.Stop()

	select {
	case <-timer.C:
		// select picks at random when both are ready, so a sleep that expires
		// exactly as the switch stops must not report success
		return sw.IsRunning()
	case <-sw.Quit():
		return false
	}
}

// IsDialingOrExistingAddress returns true if switch has a peer with the given
// address or dialing it at the moment.
func (sw *Switch) IsDialingOrExistingAddress(addr *NetAddress) bool {
	return sw.dialing.Has(string(addr.ID)) ||
		sw.peers.Has(addr.ID) ||
		(!sw.config.AllowDuplicateIP && sw.peers.HasIP(addr.IP))
}

// AddPersistentPeers allows you to set persistent peers. It ignores
// ErrNetAddressLookup. However, if there are other errors, first encounter is
// returned.
func (sw *Switch) AddPersistentPeers(addrs []string) error {
	sw.Logger.Info("Adding persistent peers", "addrs", addrs)
	netAddrs, errs := NewNetAddressStrings(addrs)
	// report all the errors
	for _, err := range errs {
		sw.Logger.Error("Error in peer's address", "err", err)
	}
	// return first non-ErrNetAddressLookup error
	for _, err := range errs {
		if _, ok := err.(ErrNetAddressLookup); ok {
			continue
		}
		return err
	}
	sw.peerCfgMtx.Lock()
	sw.persistentPeersAddrs = netAddrs
	sw.peerCfgMtx.Unlock()
	return nil
}

func (sw *Switch) AddUnconditionalPeerIDs(ids []string) error {
	sw.Logger.Info("Adding unconditional peer ids", "ids", ids)

	// validate every id before storing any, so a bad entry late in the list
	// cannot leave the set half updated
	validIDs := make([]ID, 0, len(ids))
	for i, id := range ids {
		if err := validateID(ID(id)); err != nil {
			return fmt.Errorf("wrong ID #%d: %w", i, err)
		}
		validIDs = append(validIDs, ID(id))
	}

	sw.peerCfgMtx.Lock()
	defer sw.peerCfgMtx.Unlock()

	for _, id := range validIDs {
		sw.unconditionalPeerIDs[id] = struct{}{}
	}
	return nil
}

func (sw *Switch) AddPrivatePeerIDs(ids []string) error {
	validIDs := make([]string, 0, len(ids))
	for i, id := range ids {
		err := validateID(ID(id))
		if err != nil {
			return fmt.Errorf("wrong ID #%d: %w", i, err)
		}
		validIDs = append(validIDs, id)
	}

	sw.addrBook.AddPrivateIDs(validIDs)

	return nil
}

func (sw *Switch) IsPeerPersistent(na *NetAddress) bool {
	sw.peerCfgMtx.RLock()
	defer sw.peerCfgMtx.RUnlock()

	for _, pa := range sw.persistentPeersAddrs {
		if pa.Equals(na) {
			return true
		}
	}
	return false
}

func (sw *Switch) acceptRoutine() {
	for {
		p, err := sw.transport.Accept(peerConfig{
			chDescs:       sw.chDescs,
			onPeerError:   sw.StopPeerForError,
			reactorsByCh:  sw.reactorsByCh,
			msgTypeByChID: sw.msgTypeByChID,
			metrics:       sw.metrics,
			mlc:           sw.mlc,
			isPersistent:  sw.IsPeerPersistent,
		})
		if err != nil {
			switch err := err.(type) {
			case ErrRejected:
				if err.IsSelf() {
					// Remove the given address from the address book and add to our addresses
					// to avoid dialing in the future.
					addr := err.Addr()
					sw.addrBook.RemoveAddress(&addr)
					sw.addrBook.AddOurAddress(&addr)
				}

				sw.Logger.Info(
					"Inbound Peer rejected",
					"err", err,
					"numPeers", sw.peers.Size(),
				)

				continue
			case ErrFilterTimeout:
				sw.Logger.Error(
					"Peer filter timed out",
					"err", err,
				)

				continue
			case ErrTransportClosed:
				sw.Logger.Error(
					"Stopped accept routine, as transport is closed",
					"numPeers", sw.peers.Size(),
				)
			default:
				sw.Logger.Error(
					"Accept on transport errored",
					"err", err,
					"numPeers", sw.peers.Size(),
				)
				// We could instead have a retry loop around the acceptRoutine,
				// but that would need to stop and let the node shutdown eventually.
				// So might as well panic and let process managers restart the node.
				// There's no point in letting the node run without the acceptRoutine,
				// since it won't be able to accept new connections.
				panic(fmt.Errorf("accept routine exited: %v", err))
			}

			break
		}

		if !sw.IsPeerUnconditional(p.NodeInfo().ID()) {
			// Ignore connection if we already have enough peers.
			_, in, _ := sw.NumPeers()
			if in >= sw.config.MaxNumInboundPeers {
				sw.Logger.Info(
					"Ignoring inbound connection: already have enough inbound peers",
					"address", p.SocketAddr(),
					"have", in,
					"max", sw.config.MaxNumInboundPeers,
				)

				sw.transport.Cleanup(p)

				continue
			}

		}

		if err := sw.addPeer(p); err != nil {
			sw.transport.Cleanup(p)
			if p.IsRunning() {
				_ = p.Stop()
			}
			sw.Logger.Info(
				"Ignoring inbound connection: error while adding peer",
				"err", err,
				"id", p.ID(),
			)
		}
	}
}

// dial the peer; make secret connection; authenticate against the dialed ID;
// add the peer.
// if dialing fails, start the reconnect loop. If handshake fails, it's over.
// If peer is started successfully, reconnectLoop will start when
// StopPeerForError is called.
func (sw *Switch) addOutboundPeerWithConfig(
	addr *NetAddress,
	cfg *config.P2PConfig,
) error {
	sw.Logger.Debug("Dialing peer", "address", addr)

	// XXX(xla): Remove the leakage of test concerns in implementation.
	if cfg.TestDialFail {
		go sw.reconnectToPeer(addr)
		return fmt.Errorf("dial err (peerConfig.DialFail == true)")
	}

	p, err := sw.transport.Dial(*addr, peerConfig{
		chDescs:       sw.chDescs,
		onPeerError:   sw.StopPeerForError,
		isPersistent:  sw.IsPeerPersistent,
		reactorsByCh:  sw.reactorsByCh,
		msgTypeByChID: sw.msgTypeByChID,
		metrics:       sw.metrics,
		mlc:           sw.mlc,
	})
	if err != nil {
		if e, ok := err.(ErrRejected); ok {
			if e.IsSelf() {
				// Remove the given address from the address book and add to our addresses
				// to avoid dialing in the future.
				sw.addrBook.RemoveAddress(addr)
				sw.addrBook.AddOurAddress(addr)

				return err
			}
		}

		// retry persistent peers after
		// any dial error besides IsSelf()
		if sw.IsPeerPersistent(addr) {
			go sw.reconnectToPeer(addr)
		}

		return err
	}

	if err := sw.addPeer(p); err != nil {
		sw.transport.Cleanup(p)
		if p.IsRunning() {
			_ = p.Stop()
		}
		return err
	}

	return nil
}

func (sw *Switch) filterPeer(p Peer) error {
	// Avoid duplicate
	if sw.peers.Has(p.ID()) {
		return ErrRejected{id: p.ID(), isDuplicate: true}
	}

	errc := make(chan error, len(sw.peerFilters))

	for _, f := range sw.peerFilters {
		go func(f PeerFilterFunc, p Peer, errc chan<- error) {
			errc <- f(sw.peers, p)
		}(f, p, errc)
	}

	for i := 0; i < cap(errc); i++ {
		select {
		case err := <-errc:
			if err != nil {
				return ErrRejected{id: p.ID(), err: err, isFiltered: true}
			}
		case <-time.After(sw.filterTimeout):
			return ErrFilterTimeout{}
		}
	}

	return nil
}

// addPeer starts up the Peer and adds it to the Switch. Error is returned if
// the peer is filtered out or failed to start or can't be added.
func (sw *Switch) addPeer(p Peer) error {
	if err := sw.filterPeer(p); err != nil {
		return err
	}

	p.SetLogger(sw.Logger.With("peer", p.SocketAddr()))

	// Handle the shut down case where the switch has stopped but we're
	// concurrently trying to add a peer.
	if !sw.IsRunning() {
		// XXX should this return an error or just log and terminate?
		sw.Logger.Error("Won't start a peer - switch is not running", "peer", p)
		return nil
	}

	// Add some data to the peer, which is required by reactors.
	for _, reactor := range sw.reactors {
		p = reactor.InitPeer(p)
	}

	// Start the peer's send/recv routines.
	// Must start it before adding it to the peer set
	// to prevent Start and Stop from being called concurrently.
	err := p.Start()
	if err != nil {
		// Should never happen
		sw.Logger.Error("Error starting peer", "err", err, "peer", p)
		return err
	}

	// Add the peer to PeerSet. Do this before starting the reactors
	// so that if Receive errors, we will find the peer and remove it.
	// Add should not err since we already checked peers.Has().
	if err := sw.peers.Add(p); err != nil {
		var peerRemovalErr ErrPeerRemoval
		if errors.As(err, &peerRemovalErr) {
			sw.Logger.Error("Error starting peer ",
				" err ", "Peer has already errored and removal was attempted.",
				"peer", p.ID())
		}
		return err
	}
	sw.metrics.Peers.Add(float64(1))

	// Start all the reactor protocols on the peer.
	for _, reactor := range sw.reactors {
		reactor.AddPeer(p)
	}

	sw.Logger.Debug("Added peer", "peer", p)

	return nil
}
