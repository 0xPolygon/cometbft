package p2p

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmos/gogoproto/proto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	cmtsync "github.com/cometbft/cometbft/libs/sync"
	"github.com/cometbft/cometbft/p2p/conn"
	p2pproto "github.com/cometbft/cometbft/proto/tendermint/p2p"
)

var cfg *config.P2PConfig

func init() {
	cfg = config.DefaultP2PConfig()
	cfg.PexReactor = true
	cfg.AllowDuplicateIP = true
}

type PeerMessage struct {
	Contents proto.Message
	Counter  int
}

type TestReactor struct {
	BaseReactor

	mtx          cmtsync.Mutex
	channels     []*conn.ChannelDescriptor
	logMessages  bool
	msgsCounter  int
	msgsReceived map[byte][]PeerMessage
}

func NewTestReactor(channels []*conn.ChannelDescriptor, logMessages bool) *TestReactor {
	tr := &TestReactor{
		channels:     channels,
		logMessages:  logMessages,
		msgsReceived: make(map[byte][]PeerMessage),
	}
	tr.BaseReactor = *NewBaseReactor("TestReactor", tr)
	tr.SetLogger(log.TestingLogger())
	return tr
}

func (tr *TestReactor) GetChannels() []*conn.ChannelDescriptor {
	return tr.channels
}

func (tr *TestReactor) AddPeer(Peer) {}

func (tr *TestReactor) RemovePeer(Peer, interface{}) {}

func (tr *TestReactor) Receive(e Envelope) {
	if tr.logMessages {
		tr.mtx.Lock()
		defer tr.mtx.Unlock()
		fmt.Printf("Received: %X, %X\n", e.ChannelID, e.Message)
		tr.msgsReceived[e.ChannelID] = append(tr.msgsReceived[e.ChannelID], PeerMessage{Contents: e.Message, Counter: tr.msgsCounter})
		tr.msgsCounter++
	}
}

func (tr *TestReactor) getMsgs(chID byte) []PeerMessage {
	tr.mtx.Lock()
	defer tr.mtx.Unlock()
	return tr.msgsReceived[chID]
}

//-----------------------------------------------------------------------------

// convenience method for creating two switches connected to each other.
// XXX: note this uses net.Pipe and not a proper TCP conn
func MakeSwitchPair(initSwitch func(int, *Switch) *Switch) (*Switch, *Switch) {
	// Create two switches that will be interconnected.
	switches := MakeConnectedSwitches(cfg, 2, initSwitch, Connect2Switches)
	return switches[0], switches[1]
}

func initSwitchFunc(_ int, sw *Switch) *Switch {
	sw.SetAddrBook(&AddrBookMock{
		Addrs:    make(map[string]struct{}),
		OurAddrs: make(map[string]struct{}),
	})

	// Make two reactors of two channels each
	sw.AddReactor("foo", NewTestReactor([]*conn.ChannelDescriptor{
		{ID: byte(0x00), Priority: 10, MessageType: &p2pproto.Message{}},
		{ID: byte(0x01), Priority: 10, MessageType: &p2pproto.Message{}},
	}, true))
	sw.AddReactor("bar", NewTestReactor([]*conn.ChannelDescriptor{
		{ID: byte(0x02), Priority: 10, MessageType: &p2pproto.Message{}},
		{ID: byte(0x03), Priority: 10, MessageType: &p2pproto.Message{}},
	}, true))

	return sw
}

func TestSwitches(t *testing.T) {
	s1, s2 := MakeSwitchPair(initSwitchFunc)
	t.Cleanup(func() {
		if err := s1.Stop(); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(func() {
		if err := s2.Stop(); err != nil {
			t.Error(err)
		}
	})

	if s1.Peers().Size() != 1 {
		t.Errorf("expected exactly 1 peer in s1, got %v", s1.Peers().Size())
	}
	if s2.Peers().Size() != 1 {
		t.Errorf("expected exactly 1 peer in s2, got %v", s2.Peers().Size())
	}

	// Lets send some messages
	ch0Msg := &p2pproto.PexAddrs{
		Addrs: []p2pproto.NetAddress{
			{
				ID: "1",
			},
		},
	}
	ch1Msg := &p2pproto.PexAddrs{
		Addrs: []p2pproto.NetAddress{
			{
				ID: "1",
			},
		},
	}
	ch2Msg := &p2pproto.PexAddrs{
		Addrs: []p2pproto.NetAddress{
			{
				ID: "2",
			},
		},
	}
	s1.Broadcast(Envelope{ChannelID: byte(0x00), Message: ch0Msg})
	s1.Broadcast(Envelope{ChannelID: byte(0x01), Message: ch1Msg})
	s1.Broadcast(Envelope{ChannelID: byte(0x02), Message: ch2Msg})
	assertMsgReceivedWithTimeout(t,
		ch0Msg,
		byte(0x00),
		s2.Reactor("foo").(*TestReactor), 200*time.Millisecond, 5*time.Second)
	assertMsgReceivedWithTimeout(t,
		ch1Msg,
		byte(0x01),
		s2.Reactor("foo").(*TestReactor), 200*time.Millisecond, 5*time.Second)
	assertMsgReceivedWithTimeout(t,
		ch2Msg,
		byte(0x02),
		s2.Reactor("bar").(*TestReactor), 200*time.Millisecond, 5*time.Second)
}

func assertMsgReceivedWithTimeout(
	t *testing.T,
	msg proto.Message,
	channel byte,
	reactor *TestReactor,
	checkPeriod,
	timeout time.Duration,
) {
	ticker := time.NewTicker(checkPeriod)
	for {
		select {
		case <-ticker.C:
			msgs := reactor.getMsgs(channel)
			expectedBytes, err := proto.Marshal(msgs[0].Contents)
			require.NoError(t, err)
			gotBytes, err := proto.Marshal(msg)
			require.NoError(t, err)
			if len(msgs) > 0 {
				if !bytes.Equal(expectedBytes, gotBytes) {
					t.Fatalf("Unexpected message bytes. Wanted: %X, Got: %X", msg, msgs[0].Counter)
				}
				return
			}

		case <-time.After(timeout):
			t.Fatalf("Expected to have received 1 message in channel #%v, got zero", channel)
		}
	}
}

func TestSwitchFiltersOutItself(t *testing.T) {
	s1 := MakeSwitch(cfg, 1, initSwitchFunc)

	// simulate s1 having a public IP by creating a remote peer with the same ID
	rp := &remotePeer{PrivKey: s1.nodeKey.PrivKey, Config: cfg}
	rp.Start()

	// addr should be rejected in addPeer based on the same ID
	err := s1.DialPeerWithAddress(rp.Addr())
	if assert.Error(t, err) {
		if err, ok := err.(ErrRejected); ok {
			if !err.IsSelf() {
				t.Errorf("expected self to be rejected")
			}
		} else {
			t.Errorf("expected ErrRejected")
		}
	}

	assert.True(t, s1.addrBook.OurAddress(rp.Addr()))
	assert.False(t, s1.addrBook.HasAddress(rp.Addr()))

	rp.Stop()

	assertNoPeersAfterTimeout(t, s1, 100*time.Millisecond)
}

func TestSwitchPeerFilter(t *testing.T) {
	var (
		filters = []PeerFilterFunc{
			func(_ IPeerSet, _ Peer) error { return nil },
			func(_ IPeerSet, _ Peer) error { return fmt.Errorf("denied") },
			func(_ IPeerSet, _ Peer) error { return nil },
		}
		sw = MakeSwitch(
			cfg,
			1,
			initSwitchFunc,
			SwitchPeerFilters(filters...),
		)
	)
	err := sw.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	// simulate remote peer
	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	rp.Start()
	t.Cleanup(rp.Stop)

	p, err := sw.transport.Dial(*rp.Addr(), peerConfig{
		chDescs:      sw.chDescs,
		onPeerError:  sw.StopPeerForError,
		isPersistent: sw.IsPeerPersistent,
		reactorsByCh: sw.reactorsByCh,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = sw.addPeer(p)
	if err, ok := err.(ErrRejected); ok {
		if !err.IsFiltered() {
			t.Errorf("expected peer to be filtered")
		}
	} else {
		t.Errorf("expected ErrRejected")
	}
}

func TestSwitchPeerFilterTimeout(t *testing.T) {
	var (
		filters = []PeerFilterFunc{
			func(_ IPeerSet, _ Peer) error {
				time.Sleep(10 * time.Millisecond)
				return nil
			},
		}
		sw = MakeSwitch(
			cfg,
			1,
			initSwitchFunc,
			SwitchFilterTimeout(5*time.Millisecond),
			SwitchPeerFilters(filters...),
		)
	)
	err := sw.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Log(err)
		}
	})

	// simulate remote peer
	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	rp.Start()
	defer rp.Stop()

	p, err := sw.transport.Dial(*rp.Addr(), peerConfig{
		chDescs:      sw.chDescs,
		onPeerError:  sw.StopPeerForError,
		isPersistent: sw.IsPeerPersistent,
		reactorsByCh: sw.reactorsByCh,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = sw.addPeer(p)
	if _, ok := err.(ErrFilterTimeout); !ok {
		t.Errorf("expected ErrFilterTimeout")
	}
}

func TestSwitchPeerFilterDuplicate(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	err := sw.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	// simulate remote peer
	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	rp.Start()
	defer rp.Stop()

	p, err := sw.transport.Dial(*rp.Addr(), peerConfig{
		chDescs:      sw.chDescs,
		onPeerError:  sw.StopPeerForError,
		isPersistent: sw.IsPeerPersistent,
		reactorsByCh: sw.reactorsByCh,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := sw.addPeer(p); err != nil {
		t.Fatal(err)
	}

	err = sw.addPeer(p)
	if errRej, ok := err.(ErrRejected); ok {
		if !errRej.IsDuplicate() {
			t.Errorf("expected peer to be duplicate. got %v", errRej)
		}
	} else {
		t.Errorf("expected ErrRejected, got %v", err)
	}
}

func assertNoPeersAfterTimeout(t *testing.T, sw *Switch, timeout time.Duration) {
	time.Sleep(timeout)
	if sw.Peers().Size() != 0 {
		t.Fatalf("Expected %v to not connect to some peers, got %d", sw, sw.Peers().Size())
	}
}

func TestSwitchStopsNonPersistentPeerOnError(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	err := sw.Start()
	if err != nil {
		t.Error(err)
	}
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	// simulate remote peer
	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	rp.Start()
	defer rp.Stop()

	p, err := sw.transport.Dial(*rp.Addr(), peerConfig{
		chDescs:      sw.chDescs,
		onPeerError:  sw.StopPeerForError,
		isPersistent: sw.IsPeerPersistent,
		reactorsByCh: sw.reactorsByCh,
	})
	require.Nil(err)

	err = sw.addPeer(p)
	require.Nil(err)

	require.NotNil(sw.Peers().Get(rp.ID()))

	// simulate failure by closing connection
	err = p.(*peer).CloseConn()
	require.NoError(err)

	assertNoPeersAfterTimeout(t, sw, 100*time.Millisecond)
	assert.False(p.IsRunning())
}

func TestSwitchStopPeerForError(t *testing.T) {
	s := httptest.NewServer(promhttp.Handler())
	defer s.Close()

	scrapeMetrics := func() string {
		resp, err := http.Get(s.URL)
		require.NoError(t, err)
		defer resp.Body.Close()
		buf, _ := io.ReadAll(resp.Body)
		return string(buf)
	}

	namespace, subsystem, name := config.TestInstrumentationConfig().Namespace, MetricsSubsystem, "peers"
	re := regexp.MustCompile(namespace + `_` + subsystem + `_` + name + ` ([0-9\.]+)`)
	peersMetricValue := func() float64 {
		matches := re.FindStringSubmatch(scrapeMetrics())
		f, _ := strconv.ParseFloat(matches[1], 64)
		return f
	}

	p2pMetrics := PrometheusMetrics(namespace)

	// make two connected switches
	sw1, sw2 := MakeSwitchPair(func(i int, sw *Switch) *Switch {
		// set metrics on sw1
		if i == 0 {
			opt := WithMetrics(p2pMetrics)
			opt(sw)
		}
		return initSwitchFunc(i, sw)
	})

	assert.Equal(t, len(sw1.Peers().List()), 1)
	assert.EqualValues(t, 1, peersMetricValue())

	// send messages to the peer from sw1
	p := sw1.Peers().List()[0]
	p.Send(Envelope{
		ChannelID: 0x1,
		Message:   &p2pproto.Message{},
	})

	// stop sw2. this should cause the p to fail,
	// which results in calling StopPeerForError internally
	t.Cleanup(func() {
		if err := sw2.Stop(); err != nil {
			t.Error(err)
		}
	})

	// now call StopPeerForError explicitly, eg. from a reactor
	sw1.StopPeerForError(p, fmt.Errorf("some err"))

	assert.Equal(t, len(sw1.Peers().List()), 0)
	assert.EqualValues(t, 0, peersMetricValue())
}

func TestSwitchReconnectsToOutboundPersistentPeer(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	err := sw.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	// 1. simulate failure by closing connection
	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	rp.Start()
	defer rp.Stop()

	err = sw.AddPersistentPeers([]string{rp.Addr().String()})
	require.NoError(t, err)

	err = sw.DialPeerWithAddress(rp.Addr())
	require.Nil(t, err)
	require.NotNil(t, sw.Peers().Get(rp.ID()))

	p := sw.Peers().List()[0]
	err = p.(*peer).CloseConn()
	require.NoError(t, err)

	waitUntilSwitchHasAtLeastNPeers(sw, 1)
	assert.False(t, p.IsRunning())        // old peer instance
	assert.Equal(t, 1, sw.Peers().Size()) // new peer instance

	// 2. simulate first time dial failure
	rp = &remotePeer{
		PrivKey: ed25519.GenPrivKey(),
		Config:  cfg,
		// Use different interface to prevent duplicate IP filter, this will break
		// beyond two peers.
		listenAddr: "127.0.0.1:0",
	}
	rp.Start()
	defer rp.Stop()

	conf := config.DefaultP2PConfig()
	conf.TestDialFail = true // will trigger a reconnect
	err = sw.addOutboundPeerWithConfig(rp.Addr(), conf)
	require.NotNil(t, err)
	// DialPeerWithAddres - sw.peerConfig resets the dialer
	waitUntilSwitchHasAtLeastNPeers(sw, 2)
	assert.Equal(t, 2, sw.Peers().Size())
}

func TestSwitchReconnectsToInboundPersistentPeer(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	err := sw.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	// 1. simulate failure by closing the connection
	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	rp.Start()
	defer rp.Stop()

	err = sw.AddPersistentPeers([]string{rp.Addr().String()})
	require.NoError(t, err)

	conn, err := rp.Dial(sw.NetAddress())
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	require.NotNil(t, sw.Peers().Get(rp.ID()))

	conn.Close()

	waitUntilSwitchHasAtLeastNPeers(sw, 1)
	assert.Equal(t, 1, sw.Peers().Size())
}

// blackholePeer owns a listening port but never completes a handshake: it
// counts each connection attempt and closes it, so dials to its address fail
// fast. Keeping the listener open means the port is never free for another
// process to claim, and the attempt count lets a test assert the reconnect
// loop is really dialing instead of waiting out a wall-clock margin.
type blackholePeer struct {
	key      crypto.PrivKey
	ln       net.Listener
	attempts atomic.Int64
	handOver chan struct{}
}

func newBlackholePeer(t *testing.T) *blackholePeer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	bp := &blackholePeer{
		key:      ed25519.GenPrivKey(),
		ln:       ln,
		handOver: make(chan struct{}),
	}
	t.Cleanup(func() { _ = bp.ln.Close() })

	go func() {
		for {
			conn, err := bp.ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()

			select {
			case <-bp.handOver:
				return
			default:
				bp.attempts.Add(1)
			}
		}
	}()

	return bp
}

func (bp *blackholePeer) addr() *NetAddress {
	return NewNetAddress(PubKeyToID(bp.key.PubKey()), bp.ln.Addr())
}

// waitForDials waits until the address has been dialed at least n times.
func (bp *blackholePeer) waitForDials(t *testing.T, n int64, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if bp.attempts.Load() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected at least %d dial attempts, got %d", n, bp.attempts.Load())
}

// revive serves real handshakes on the same listener under the same identity,
// so the peer becomes reachable at its original address without the port ever
// being released.
func (bp *blackholePeer) revive() {
	close(bp.handOver)

	rp := &remotePeer{
		PrivKey:  bp.key,
		Config:   cfg,
		listener: bp.ln,
		addr:     bp.addr(),
		channels: []byte{testCh},
	}
	go rp.accept()
}

// testReconnectPolicy collapses the production schedule to the shortest one
// that still runs every phase, so a test reaches the point where the old code
// abandoned the address. The two bounded phases allow exactly two dials, so any
// dial beyond that came from the persistent phase.
func testReconnectPolicy() reconnectPolicy {
	return reconnectPolicy{
		attempts:        1,
		interval:        time.Millisecond,
		backOffAttempts: 1,
		backOffBase:     1,
		persistentEvery: time.Millisecond,
	}
}

const boundedPhaseDials = 2

func TestReconnectToPeerNeverGivesUpOnPersistentPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	bp := newBlackholePeer(t)
	addr := bp.addr()
	require.NoError(t, sw.AddPersistentPeers([]string{addr.String()}))

	done := make(chan struct{})
	go func() {
		defer close(done)
		sw.reconnectToPeerWithPolicy(addr, testReconnectPolicy())
	}()

	// dials beyond what the bounded phases allow can only come from the
	// persistent phase, which is where the old code gave up instead
	bp.waitForDials(t, boundedPhaseDials+2, 30*time.Second)

	select {
	case <-done:
		t.Fatal("reconnectToPeer abandoned a persistent peer")
	default:
	}
}

func TestReconnectToPeerGivesUpOnNonPersistentPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	bp := newBlackholePeer(t)
	addr := bp.addr()
	require.False(t, sw.IsPeerPersistent(addr))

	done := make(chan struct{})
	go func() {
		defer close(done)
		sw.reconnectToPeerWithPolicy(addr, testReconnectPolicy())
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("reconnectToPeer never gave up on a non-persistent peer")
	}
	assert.LessOrEqual(t, bp.attempts.Load(), int64(boundedPhaseDials),
		"a non-persistent peer should not be dialed beyond the bounded phases")
}

func TestSwitchKeepsDialingPersistentPeerUntilItIsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	bp := newBlackholePeer(t)
	addr := bp.addr()
	require.NoError(t, sw.AddPersistentPeers([]string{addr.String()}))

	// production enters this loop through reconnectToPeerWithPolicy, which holds
	// the reconnecting guard; without it a failed dial spawns a second,
	// default-policy reconnect goroutine that also dials addr
	sw.reconnecting.Set(string(addr.ID), addr)

	done := make(chan struct{})
	go func() {
		defer close(done)
		sw.keepDialingPersistentPeer(addr, time.Millisecond)
	}()

	// repeated dial failures must not make the switch abandon the address
	bp.waitForDials(t, 3, 30*time.Second)
	select {
	case <-done:
		t.Fatal("stopped reconnecting to a persistent peer that was still unreachable")
	default:
	}

	bp.revive()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("did not reconnect after the persistent peer became reachable again")
	}
	assert.NotNil(t, sw.Peers().Get(addr.ID))
}

func TestSwitchStopsDialingWhenPeerIsNoLongerPersistent(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	bp := newBlackholePeer(t)
	addr := bp.addr()
	require.NoError(t, sw.AddPersistentPeers([]string{addr.String()}))

	// production enters this loop through reconnectToPeerWithPolicy, which holds
	// the reconnecting guard; without it a failed dial spawns a second,
	// default-policy reconnect goroutine that also dials addr
	sw.reconnecting.Set(string(addr.ID), addr)

	done := make(chan struct{})
	go func() {
		defer close(done)
		sw.keepDialingPersistentPeer(addr, time.Millisecond)
	}()

	// de-configure only once the loop is demonstrably iterating, otherwise this
	// would exercise the entry guard rather than the per-iteration re-check
	bp.waitForDials(t, 2, 30*time.Second)
	require.NoError(t, sw.AddPersistentPeers([]string{}))

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("kept reconnecting to an address that is no longer persistent")
	}
}

// An address that was never configured as persistent is still abandoned, so
// reconnectToPeer keeps its bounded behavior for everything else.
func TestSwitchDoesNotDialNonPersistentPeerIndefinitely(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	addr := newBlackholePeer(t).addr()
	require.False(t, sw.IsPeerPersistent(addr))

	// production enters this loop through reconnectToPeerWithPolicy, which holds
	// the reconnecting guard; without it a failed dial spawns a second,
	// default-policy reconnect goroutine that also dials addr
	sw.reconnecting.Set(string(addr.ID), addr)

	done := make(chan struct{})
	go func() {
		defer close(done)
		sw.keepDialingPersistentPeer(addr, time.Hour)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("kept reconnecting to an address that was never persistent")
	}
}

func TestSwitchStopsDialingPersistentPeerOnShutdown(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())

	addr := newBlackholePeer(t).addr()
	require.NoError(t, sw.AddPersistentPeers([]string{addr.String()}))

	done := make(chan struct{})
	go func() {
		defer close(done)
		// an interval far longer than the test: only shutdown can end this loop
		sw.keepDialingPersistentPeer(addr, time.Hour)
	}()

	require.NoError(t, sw.Stop())

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reconnect loop outlived the switch")
	}
}

func TestSwitchDialPeersAsyncStopsOnShutdown(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())

	bp := newBlackholePeer(t)
	require.NoError(t, sw.Stop())

	// every dial goroutine sleeps before dialing, so a stopped switch must
	// abandon the dial rather than attempt it
	sw.dialPeersAsync([]*NetAddress{bp.addr()})
	time.Sleep(dialRandomizerIntervalMilliseconds*time.Millisecond + time.Second)

	assert.Zero(t, bp.attempts.Load(), "a stopped switch should not dial")
}

func TestSwitchAddPersistentPeers(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})
	addr := newBlackholePeer(t).addr()

	// cases run in order against the same switch: the set is replaced, not
	// extended, so clearing is only meaningful after something was added
	testCases := []struct {
		name        string
		peers       []string
		expectError bool
		persistent  bool
	}{
		{name: "valid address", peers: []string{addr.String()}, persistent: true},
		{name: "empty list clears the set", peers: []string{}},
		{name: "missing id", peers: []string{addr.DialString()}, expectError: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			before := sw.IsPeerPersistent(addr)

			err := sw.AddPersistentPeers(tc.peers)
			if tc.expectError {
				require.Error(t, err)
				assert.Equal(t, before, sw.IsPeerPersistent(addr),
					"a rejected input should leave the previous set untouched")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.persistent, sw.IsPeerPersistent(addr))
		})
	}
}

func TestSwitchAddUnconditionalPeerIDs(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	id := string(newBlackholePeer(t).addr().ID)
	require.False(t, sw.IsPeerUnconditional(ID(id)))

	require.NoError(t, sw.AddUnconditionalPeerIDs([]string{id}))
	assert.True(t, sw.IsPeerUnconditional(ID(id)))

	other := string(newBlackholePeer(t).addr().ID)
	require.Error(t, sw.AddUnconditionalPeerIDs([]string{other, "nonsense"}))
	assert.False(t, sw.IsPeerUnconditional(ID(other)),
		"a rejected batch should not be applied partially")
	assert.True(t, sw.IsPeerUnconditional(ID(id)), "earlier ids should survive")
}

// unsafe_dial_peers mutates the configured peer sets while the accept and pex
// paths read them. An unguarded map here is a fatal throw, not a recoverable
// panic, so this has to be race-clean.
func TestSwitchConfiguredPeerSetsAreRaceFree(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	addr := newBlackholePeer(t).addr()
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// writers: the unsafe_dial_peers RPC path
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = sw.AddUnconditionalPeerIDs([]string{string(PubKeyToID(ed25519.GenPrivKey().PubKey()))})
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = sw.AddPersistentPeers([]string{addr.String()})
		}
	}()

	// readers: NumPeers (pex ensurePeers), the accept path, and reconnect
	wg.Add(3)
	for range 3 {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				sw.NumPeers()
				sw.IsPeerUnconditional(addr.ID)
				sw.IsPeerPersistent(addr)
			}
		}()
	}

	time.Sleep(250 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// An address removed while the loop is asleep must not get one more dial, or
// the switch could reconnect a peer the operator just took out of the set.
func TestSwitchDoesNotDialPeerDeconfiguredDuringSleep(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	bp := newBlackholePeer(t)
	addr := bp.addr()
	require.NoError(t, sw.AddPersistentPeers([]string{addr.String()}))
	sw.reconnecting.Set(string(addr.ID), addr)

	done := make(chan struct{})
	go func() {
		defer close(done)
		sw.keepDialingPersistentPeer(addr, 3*time.Second)
	}()

	// wait for a dial so the loop is known to be running, which puts it at the
	// start of the next sleep and leaves a wide window to de-configure in
	bp.waitForDials(t, 1, 30*time.Second)
	dialsBefore := bp.attempts.Load()
	require.NoError(t, sw.AddPersistentPeers([]string{}))

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("kept reconnecting to an address that is no longer persistent")
	}
	assert.Equal(t, dialsBefore, bp.attempts.Load(),
		"no further dial should happen after the address was removed")
}

// The configured value is a maximum pause, so the interval plus the jitter
// randomSleep adds must stay within it.
func TestSwitchPersistentRedialInterval(t *testing.T) {
	testCases := []struct {
		name    string
		maxDial time.Duration
		cap     time.Duration
	}{
		{name: "unset falls back to the default", maxDial: 0, cap: reconnectPersistentInterval},
		{name: "longer than the default is ignored", maxDial: time.Hour, cap: reconnectPersistentInterval},
		{name: "shorter than the default caps the pause", maxDial: time.Minute, cap: time.Minute},
		{name: "below the floor is clamped", maxDial: time.Millisecond, cap: reconnectInterval},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := config.DefaultP2PConfig()
			conf.PersistentPeersMaxDialPeriod = tc.maxDial
			sw := MakeSwitch(conf, 1, initSwitchFunc)

			interval := sw.persistentRedialInterval()
			assert.Equal(t, tc.cap-maxDialRandomizerInterval, interval)
			assert.Equal(t, interval+maxDialRandomizerInterval, tc.cap,
				"the longest possible sleep must not exceed the configured maximum")
			assert.Equal(t, interval, sw.defaultReconnectPolicy().persistentEvery)
		})
	}
}

func TestIsTerminalDialErr(t *testing.T) {
	assert.False(t, isTerminalDialErr(nil))
	assert.False(t, isTerminalDialErr(errors.New("connection refused")))
	assert.False(t, isTerminalDialErr(ErrCurrentlyDialingOrExistingAddress{}))

	self := ErrRejected{isSelf: true}
	assert.True(t, isTerminalDialErr(self), "our own address can never be dialed")

	// an unexpected key may just be a peer mid-upgrade, so it must stay retryable
	assert.False(t, isTerminalDialErr(ErrRejected{isAuthFailure: true}))
}

func TestSwitchRandomSleepReportsShutdown(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())

	assert.True(t, sw.randomSleep(0), "a sleep that ran to completion should report true")

	slept := make(chan bool, 1)
	go func() { slept <- sw.randomSleep(time.Hour) }()

	// the interval has to be honored, not just the jitter
	select {
	case <-slept:
		t.Fatal("randomSleep returned before its interval elapsed")
	case <-time.After(dialRandomizerIntervalMilliseconds*time.Millisecond + time.Second):
	}

	require.NoError(t, sw.Stop())

	select {
	case completed := <-slept:
		assert.False(t, completed, "a sleep cut short by shutdown should report false")
	case <-time.After(5 * time.Second):
		t.Fatal("randomSleep ignored switch shutdown")
	}
}

func TestSwitchDialForReconnect(t *testing.T) {
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	require.NoError(t, sw.Start())

	downAddr := newBlackholePeer(t).addr()
	assert.False(t, sw.dialForReconnect(downAddr, 0), "a failed dial should keep the loop going")

	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	rp.Start()
	defer rp.Stop()

	assert.True(t, sw.dialForReconnect(rp.Addr(), 0), "a successful dial should end the loop")
	assert.True(t, sw.dialForReconnect(rp.Addr(), 0), "an already-connected peer should end the loop")

	require.NoError(t, sw.Stop())
	assert.True(t, sw.dialForReconnect(downAddr, 0), "a stopped switch should end the loop")
}

func TestSwitchDialPeersAsync(t *testing.T) {
	if testing.Short() {
		return
	}

	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	err := sw.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	rp.Start()
	defer rp.Stop()

	err = sw.DialPeersAsync([]string{rp.Addr().String()})
	require.NoError(t, err)
	time.Sleep(dialRandomizerIntervalMilliseconds * time.Millisecond)
	require.NotNil(t, sw.Peers().Get(rp.ID()))
}

func waitUntilSwitchHasAtLeastNPeers(sw *Switch, n int) {
	for i := 0; i < 20; i++ {
		time.Sleep(250 * time.Millisecond)
		has := sw.Peers().Size()
		if has >= n {
			break
		}
	}
}

func TestSwitchFullConnectivity(t *testing.T) {
	switches := MakeConnectedSwitches(cfg, 3, initSwitchFunc, Connect2Switches)
	defer func() {
		for _, sw := range switches {

			t.Cleanup(func() {
				if err := sw.Stop(); err != nil {
					t.Error(err)
				}
			})
		}
	}()

	for i, sw := range switches {
		if sw.Peers().Size() != 2 {
			t.Fatalf("Expected each switch to be connected to 2 other, but %d switch only connected to %d", sw.Peers().Size(), i)
		}
	}
}

func TestSwitchAcceptRoutine(t *testing.T) {
	cfg.MaxNumInboundPeers = 5

	// Create some unconditional peers.
	const unconditionalPeersNum = 2
	var (
		unconditionalPeers   = make([]*remotePeer, unconditionalPeersNum)
		unconditionalPeerIDs = make([]string, unconditionalPeersNum)
	)
	for i := 0; i < unconditionalPeersNum; i++ {
		peer := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
		peer.Start()
		unconditionalPeers[i] = peer
		unconditionalPeerIDs[i] = string(peer.ID())
	}

	// make switch
	sw := MakeSwitch(cfg, 1, initSwitchFunc)
	err := sw.AddUnconditionalPeerIDs(unconditionalPeerIDs)
	require.NoError(t, err)
	err = sw.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		err := sw.Stop()
		require.NoError(t, err)
	})

	// 0. check there are no peers
	assert.Equal(t, 0, sw.Peers().Size())

	// 1. check we connect up to MaxNumInboundPeers
	peers := make([]*remotePeer, 0)
	for i := 0; i < cfg.MaxNumInboundPeers; i++ {
		peer := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
		peers = append(peers, peer)
		peer.Start()
		c, err := peer.Dial(sw.NetAddress())
		require.NoError(t, err)
		// spawn a reading routine to prevent connection from closing
		go func(c net.Conn) {
			for {
				one := make([]byte, 1)
				_, err := c.Read(one)
				if err != nil {
					return
				}
			}
		}(c)
	}
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, cfg.MaxNumInboundPeers, sw.Peers().Size())

	// 2. check we close new connections if we already have MaxNumInboundPeers peers
	peer := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	peer.Start()
	conn, err := peer.Dial(sw.NetAddress())
	require.NoError(t, err)
	// check conn is closed
	one := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	_, err = conn.Read(one)
	assert.Error(t, err)
	assert.Equal(t, cfg.MaxNumInboundPeers, sw.Peers().Size())
	peer.Stop()

	// 3. check we connect to unconditional peers despite the limit.
	for _, peer := range unconditionalPeers {
		c, err := peer.Dial(sw.NetAddress())
		require.NoError(t, err)
		// spawn a reading routine to prevent connection from closing
		go func(c net.Conn) {
			for {
				one := make([]byte, 1)
				_, err := c.Read(one)
				if err != nil {
					return
				}
			}
		}(c)
	}
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, cfg.MaxNumInboundPeers+unconditionalPeersNum, sw.Peers().Size())

	for _, peer := range peers {
		peer.Stop()
	}
	for _, peer := range unconditionalPeers {
		peer.Stop()
	}
}

type errorTransport struct {
	acceptErr error
}

func (et errorTransport) NetAddress() NetAddress {
	panic("not implemented")
}

func (et errorTransport) Accept(peerConfig) (Peer, error) {
	return nil, et.acceptErr
}

func (errorTransport) Dial(NetAddress, peerConfig) (Peer, error) {
	panic("not implemented")
}

func (errorTransport) Cleanup(Peer) {
	panic("not implemented")
}

func TestSwitchAcceptRoutineErrorCases(t *testing.T) {
	sw := NewSwitch(cfg, errorTransport{ErrFilterTimeout{}})
	assert.NotPanics(t, func() {
		err := sw.Start()
		require.NoError(t, err)
		err = sw.Stop()
		require.NoError(t, err)
	})

	sw = NewSwitch(cfg, errorTransport{ErrRejected{conn: nil, err: errors.New("filtered"), isFiltered: true}})
	assert.NotPanics(t, func() {
		err := sw.Start()
		require.NoError(t, err)
		err = sw.Stop()
		require.NoError(t, err)
	})
	// TODO(melekes) check we remove our address from addrBook

	sw = NewSwitch(cfg, errorTransport{ErrTransportClosed{}})
	assert.NotPanics(t, func() {
		err := sw.Start()
		require.NoError(t, err)
		err = sw.Stop()
		require.NoError(t, err)
	})
}

// mockReactor checks that InitPeer never called before RemovePeer. If that's
// not true, InitCalledBeforeRemoveFinished will return true.
type mockReactor struct {
	*BaseReactor

	// atomic
	removePeerInProgress           uint32
	initCalledBeforeRemoveFinished uint32
}

func (r *mockReactor) RemovePeer(Peer, interface{}) {
	atomic.StoreUint32(&r.removePeerInProgress, 1)
	defer atomic.StoreUint32(&r.removePeerInProgress, 0)
	time.Sleep(100 * time.Millisecond)
}

func (r *mockReactor) InitPeer(peer Peer) Peer {
	if atomic.LoadUint32(&r.removePeerInProgress) == 1 {
		atomic.StoreUint32(&r.initCalledBeforeRemoveFinished, 1)
	}

	return peer
}

func (r *mockReactor) InitCalledBeforeRemoveFinished() bool {
	return atomic.LoadUint32(&r.initCalledBeforeRemoveFinished) == 1
}

// see stopAndRemovePeer
func TestSwitchInitPeerIsNotCalledBeforeRemovePeer(t *testing.T) {
	// make reactor
	reactor := &mockReactor{}
	reactor.BaseReactor = NewBaseReactor("mockReactor", reactor)

	// make switch
	sw := MakeSwitch(cfg, 1, func(i int, sw *Switch) *Switch {
		sw.AddReactor("mock", reactor)
		return sw
	})
	err := sw.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Error(err)
		}
	})

	// add peer
	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	rp.Start()
	defer rp.Stop()
	_, err = rp.Dial(sw.NetAddress())
	require.NoError(t, err)

	// wait till the switch adds rp to the peer set, then stop the peer asynchronously
	for {
		time.Sleep(20 * time.Millisecond)
		if peer := sw.Peers().Get(rp.ID()); peer != nil {
			go sw.StopPeerForError(peer, "test")
			break
		}
	}

	// simulate peer reconnecting to us
	_, err = rp.Dial(sw.NetAddress())
	require.NoError(t, err)
	// wait till the switch adds rp to the peer set
	time.Sleep(50 * time.Millisecond)

	// make sure reactor.RemovePeer is finished before InitPeer is called
	assert.False(t, reactor.InitCalledBeforeRemoveFinished())
}

func BenchmarkSwitchBroadcast(b *testing.B) {
	s1, s2 := MakeSwitchPair(func(i int, sw *Switch) *Switch {
		// Make bar reactors of bar channels each
		sw.AddReactor("foo", NewTestReactor([]*conn.ChannelDescriptor{
			{ID: byte(0x00), Priority: 10},
			{ID: byte(0x01), Priority: 10},
		}, false))
		sw.AddReactor("bar", NewTestReactor([]*conn.ChannelDescriptor{
			{ID: byte(0x02), Priority: 10},
			{ID: byte(0x03), Priority: 10},
		}, false))
		return sw
	})

	b.Cleanup(func() {
		if err := s1.Stop(); err != nil {
			b.Error(err)
		}
	})

	b.Cleanup(func() {
		if err := s2.Stop(); err != nil {
			b.Error(err)
		}
	})

	// Allow time for goroutines to boot up
	time.Sleep(1 * time.Second)

	b.ResetTimer()

	numSuccess, numFailure := 0, 0

	// Send random message from foo channel to another
	for i := 0; i < b.N; i++ {
		chID := byte(i % 4)
		successChan := s1.Broadcast(Envelope{ChannelID: chID})
		for s := range successChan {
			if s {
				numSuccess++
			} else {
				numFailure++
			}
		}
	}

	b.Logf("success: %v, failure: %v", numSuccess, numFailure)
}

func TestSwitchRemovalErr(t *testing.T) {
	sw1, sw2 := MakeSwitchPair(initSwitchFunc)
	assert.Equal(t, len(sw1.Peers().List()), 1)
	p := sw1.Peers().List()[0]

	sw2.StopPeerForError(p, fmt.Errorf("peer should error"))

	assert.Equal(t, sw2.peers.Add(p).Error(), ErrPeerRemoval{}.Error())
}
