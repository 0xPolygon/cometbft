package p2p

import (
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/cosmos/gogoproto/proto"

	"github.com/cometbft/cometbft/libs/cmap"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/service"

	cmtconn "github.com/cometbft/cometbft/p2p/conn"
)

//go:generate ../scripts/mockery_generate.sh Peer

const metricsTickerDuration = 10 * time.Second

// Peer is an interface representing a peer connected on a reactor.
type Peer interface {
	service.Service
	FlushStop()

	ID() ID               // peer's cryptographic ID
	RemoteIP() net.IP     // remote IP of the connection
	RemoteAddr() net.Addr // remote address of the connection

	IsOutbound() bool   // did we dial the peer
	IsPersistent() bool // do we redial this peer when we disconnect

	CloseConn() error // close original connection

	NodeInfo() NodeInfo // peer's info
	Status() cmtconn.ConnectionStatus
	SocketAddr() *NetAddress // actual address of the socket

	Send(Envelope) bool
	TrySend(Envelope) bool

	Set(string, interface{})
	Get(string) interface{}

	SetRemovalFailed()
	GetRemovalFailed() bool
}

//----------------------------------------------------------

// peerConn contains the raw connection and its config.
type peerConn struct {
	outbound   bool
	persistent bool
	conn       net.Conn // source connection

	socketAddr *NetAddress
}

func newPeerConn(
	outbound, persistent bool,
	conn net.Conn,
	socketAddr *NetAddress,
) peerConn {

	return peerConn{
		outbound:   outbound,
		persistent: persistent,
		conn:       conn,
		socketAddr: socketAddr,
	}
}

// ID only exists for SecretConnection.
// NOTE: Will panic if conn is not *SecretConnection.
func (pc peerConn) ID() ID {
	return PubKeyToID(pc.conn.(*cmtconn.SecretConnection).RemotePubKey())
}

// peer implements Peer.
//
// Before using a peer, you will need to perform a handshake on connection.
type peer struct {
	service.BaseService

	// raw peerConn and the multiplex connection
	peerConn
	mconn *cmtconn.MConnection

	// cached RemoteIP(), resolved at most once. RemoteIP is called
	// concurrently in practice (this reactor's own receive goroutine, the
	// RPC net_info handler, PeerSet.hasIP), so the cache populate is
	// guarded by ipOnce rather than a plain nil-check on peerConn — a bare
	// check-then-write there would be a real data race the first time two
	// callers race to resolve it, not just a theoretical one. Lives here
	// rather than on peerConn because peerConn is constructed and passed
	// by value (newPeerConn/newPeer) before being embedded — a sync.Once
	// there would make every one of those pre-use copies a copylocks
	// violation. peer itself is never copied by value; only *peer is ever
	// used once constructed.
	//
	// sync.Once marks itself done even when f panics (see sync.Once.Do's
	// doc), so a panic in RemoteIP's resolve closure permanently poisons
	// ip to nil rather than retrying — every later call on that peer
	// silently returns nil instead of re-panicking. Not attacker-reachable
	// (RemoteAddr().String() is kernel-reported and net.LookupIP
	// short-circuits literal IPs without a DNS query), and a nil result
	// buckets harmlessly under ipRateLimitKey's shared "<nil>" key rather
	// than bypassing the rate limit — but worth knowing before assuming a
	// broken RemoteAddr() would keep erroring loudly.
	ipOnce sync.Once
	ip     net.IP

	// peer's node info and the channel it knows about
	// channels = nodeInfo.Channels
	// cached to avoid copying nodeInfo in hasChannel
	nodeInfo NodeInfo
	channels []byte

	// User data
	Data *cmap.CMap

	metrics       *Metrics
	metricsTicker *time.Ticker
	mlc           *metricsLabelCache

	// When removal of a peer fails, we set this flag
	removalAttemptFailed bool
}

type PeerOption func(*peer)

func newPeer(
	pc peerConn,
	mConfig cmtconn.MConnConfig,
	nodeInfo NodeInfo,
	reactorsByCh map[byte]Reactor,
	msgTypeByChID map[byte]proto.Message,
	chDescs []*cmtconn.ChannelDescriptor,
	onPeerError func(Peer, interface{}),
	mlc *metricsLabelCache,
	options ...PeerOption,
) *peer {
	p := &peer{
		peerConn:      pc,
		nodeInfo:      nodeInfo,
		channels:      nodeInfo.(DefaultNodeInfo).Channels,
		Data:          cmap.NewCMap(),
		metricsTicker: time.NewTicker(metricsTickerDuration),
		metrics:       NopMetrics(),
		mlc:           mlc,
	}

	p.mconn = createMConnection(
		pc.conn,
		p,
		reactorsByCh,
		msgTypeByChID,
		chDescs,
		onPeerError,
		mConfig,
	)
	p.BaseService = *service.NewBaseService(nil, "Peer", p)
	for _, option := range options {
		option(p)
	}

	return p
}

// String representation.
func (p *peer) String() string {
	if p.outbound {
		return fmt.Sprintf("Peer{%v %v out}", p.mconn, p.ID())
	}

	return fmt.Sprintf("Peer{%v %v in}", p.mconn, p.ID())
}

//---------------------------------------------------
// Implements service.Service

// SetLogger implements BaseService.
func (p *peer) SetLogger(l log.Logger) {
	p.Logger = l
	p.mconn.SetLogger(l)
}

// OnStart implements BaseService.
func (p *peer) OnStart() error {
	if err := p.BaseService.OnStart(); err != nil {
		return err
	}

	if err := p.mconn.Start(); err != nil {
		return err
	}

	go p.metricsReporter()
	return nil
}

// FlushStop mimics OnStop but additionally ensures that all successful
// .Send() calls will get flushed before closing the connection.
// NOTE: it is not safe to call this method more than once.
func (p *peer) FlushStop() {
	p.metricsTicker.Stop()
	p.BaseService.OnStop()
	p.mconn.FlushStop() // stop everything and close the conn
}

// OnStop implements BaseService.
func (p *peer) OnStop() {
	p.metricsTicker.Stop()
	p.BaseService.OnStop()
	if err := p.mconn.Stop(); err != nil { // stop everything and close the conn
		p.Logger.Debug("Error while stopping peer", "err", err)
	}
}

//---------------------------------------------------
// Implements Peer

// ID returns the peer's ID - the hex encoded hash of its pubkey.
func (p *peer) ID() ID {
	return p.nodeInfo.ID()
}

// IsOutbound returns true if the connection is outbound, false otherwise.
func (p *peer) IsOutbound() bool {
	return p.outbound
}

// IsPersistent returns true if the peer is persitent, false otherwise.
func (p *peer) IsPersistent() bool {
	return p.persistent
}

// NodeInfo returns a copy of the peer's NodeInfo.
func (p *peer) NodeInfo() NodeInfo {
	return p.nodeInfo
}

// SocketAddr returns the address of the socket.
// For outbound peers, it's the address dialed (after DNS resolution).
// For inbound peers, it's the address returned by the underlying connection
// (not what's reported in the peer's NodeInfo).
func (p *peer) SocketAddr() *NetAddress {
	return p.socketAddr
}

// Status returns the peer's ConnectionStatus.
func (p *peer) Status() cmtconn.ConnectionStatus {
	return p.mconn.Status()
}

// Send msg bytes to the channel identified by chID byte. Returns false if the
// send queue is full after timeout, specified by MConnection.
func (p *peer) Send(e Envelope) bool {
	return p.send(e.ChannelID, e.Message, p.mconn.Send)
}

// TrySendTracked transfers completion reporting to the native connection writer.
func (p *peer) TrySendTracked(e Envelope, done func(bool)) bool {
	return p.send(e.ChannelID, e.Message, func(id byte, data []byte) bool {
		return p.mconn.TrySendTracked(id, data, done)
	})
}

// TrySend returns false immediately if the channel queue is full.
func (p *peer) TrySend(e Envelope) bool {
	return p.send(e.ChannelID, e.Message, p.mconn.TrySend)
}

func (p *peer) send(chID byte, msg proto.Message, sendFunc func(byte, []byte) bool) bool {
	if !p.IsRunning() {
		return false
	} else if !p.hasChannel(chID) {
		return false
	}
	metricLabelValue := p.mlc.ValueToMetricLabel(msg)
	if w, ok := msg.(Wrapper); ok {
		msg = w.Wrap()
	}
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		p.Logger.Error("marshaling message to send", "error", err)
		return false
	}
	res := sendFunc(chID, msgBytes)
	if res {
		labels := []string{
			"peer_id", string(p.ID()),
			"chID", fmt.Sprintf("%#x", chID),
		}
		p.metrics.PeerSendBytesTotal.With(labels...).Add(float64(len(msgBytes)))
		p.metrics.MessageSendBytesTotal.With("message_type", metricLabelValue).Add(float64(len(msgBytes)))
	}
	return res
}

// Get the data for a given key.
func (p *peer) Get(key string) interface{} {
	return p.Data.Get(key)
}

// Set sets the data for the given key.
func (p *peer) Set(key string, data interface{}) {
	p.Data.Set(key, data)
}

// hasChannel returns true if the peer reported
// knowing about the given chID.
func (p *peer) hasChannel(chID byte) bool {
	for _, ch := range p.channels {
		if ch == chID {
			return true
		}
	}
	// NOTE: probably will want to remove this
	// but could be helpful while the feature is new
	p.Logger.Debug(
		"Unknown channel for peer",
		"channel",
		chID,
		"channels",
		p.channels,
	)
	return false
}

// CloseConn closes original connection. Used for cleaning up in cases where the peer had not been started at all.
func (p *peer) CloseConn() error {
	return p.conn.Close()
}

func (p *peer) SetRemovalFailed() {
	p.removalAttemptFailed = true
}

func (p *peer) GetRemovalFailed() bool {
	return p.removalAttemptFailed
}

//---------------------------------------------------
// methods only used for testing
// TODO: can we remove these?

// CloseConn closes the underlying connection
func (pc *peerConn) CloseConn() {
	pc.conn.Close()
}

// RemoteAddr returns peer's remote network address.
func (p *peer) RemoteAddr() net.Addr {
	return p.conn.RemoteAddr()
}

// RemoteIP returns the IP from the connection's RemoteAddr, resolved once
// and cached (see the ipOnce field's doc comment for why this lives here,
// synchronized, rather than as a plain nil-check on peerConn).
func (p *peer) RemoteIP() net.IP {
	p.ipOnce.Do(func() {
		host, _, err := net.SplitHostPort(p.conn.RemoteAddr().String())
		if err != nil {
			panic(err)
		}

		ips, err := net.LookupIP(host)
		if err != nil {
			panic(err)
		}

		p.ip = ips[0]
	})

	return p.ip
}

// CanSend returns true if the send queue is not full, false otherwise.
func (p *peer) CanSend(chID byte) bool {
	if !p.IsRunning() {
		return false
	}
	return p.mconn.CanSend(chID)
}

// SendQueueFull reports whether the channel has reached its send queue capacity.
func (p *peer) SendQueueFull(chID byte) bool {
	return p.mconn.SendQueueFull(chID)
}

//---------------------------------------------------

func PeerMetrics(metrics *Metrics) PeerOption {
	return func(p *peer) {
		p.metrics = metrics
	}
}

func (p *peer) metricsReporter() {
	for {
		select {
		case <-p.metricsTicker.C:
			status := p.mconn.Status()
			var sendQueueSize float64
			for _, chStatus := range status.Channels {
				sendQueueSize += float64(chStatus.SendQueueSize)
			}

			p.metrics.PeerPendingSendBytes.With("peer_id", string(p.ID())).Set(sendQueueSize)
		case <-p.Quit():
			return
		}
	}
}

//------------------------------------------------------------------
// helper funcs

func createMConnection(
	conn net.Conn,
	p *peer,
	reactorsByCh map[byte]Reactor,
	msgTypeByChID map[byte]proto.Message,
	chDescs []*cmtconn.ChannelDescriptor,
	onPeerError func(Peer, interface{}),
	config cmtconn.MConnConfig,
) *cmtconn.MConnection {

	onReceive := func(chID byte, msgBytes []byte) {
		reactor := reactorsByCh[chID]
		if reactor == nil {
			// Note that its ok to panic here as it's caught in the conn._recover,
			// which does onPeerError.
			panic(fmt.Sprintf("Unknown channel %X", chID))
		}
		mt := msgTypeByChID[chID]
		msg := proto.Clone(mt)
		err := proto.Unmarshal(msgBytes, msg)
		if err != nil {
			panic(fmt.Errorf("unmarshaling message: %s into type: %s", err, reflect.TypeOf(mt)))
		}
		labels := []string{
			"peer_id", string(p.ID()),
			"chID", fmt.Sprintf("%#x", chID),
		}
		if w, ok := msg.(Unwrapper); ok {
			msg, err = w.Unwrap()
			if err != nil {
				panic(fmt.Errorf("unwrapping message: %s", err))
			}
		}
		p.metrics.PeerReceiveBytesTotal.With(labels...).Add(float64(len(msgBytes)))
		p.metrics.MessageReceiveBytesTotal.With("message_type", p.mlc.ValueToMetricLabel(msg)).Add(float64(len(msgBytes)))
		reactor.Receive(Envelope{
			ChannelID: chID,
			Src:       p,
			Message:   msg,
		})
	}

	onError := func(r interface{}) {
		onPeerError(p, r)
	}

	return cmtconn.NewMConnectionWithConfig(
		conn,
		chDescs,
		onReceive,
		onError,
		config,
	)
}
