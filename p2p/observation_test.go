package p2p

import (
	"sync"
	"testing"
	"time"

	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/p2p/conn"
	"github.com/cometbft/cometbft/p2p/observation"
	pp "github.com/cometbft/cometbft/proto/tendermint/p2p"
)

type observationRecord struct {
	id    string
	event observation.Event
}
type testObserver struct {
	mu     sync.Mutex
	events []observationRecord
}

func (o *testObserver) Observe(id string, e observation.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	// Clone only in the test to assert borrowed message contents later.
	if e.Message != nil {
		e.Message = proto.Clone(e.Message)
	}
	o.events = append(o.events, observationRecord{id, e})
}
func (o *testObserver) snapshot() []observationRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]observationRecord(nil), o.events...)
}

func TestPeerObservationSendOutcome(t *testing.T) {
	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	rp.Start()
	t.Cleanup(rp.Stop)
	p, err := createOutboundPeerAndPerformHandshake(rp.Addr(), cfg, conn.DefaultMConnConfig())
	require.NoError(t, err)
	observer := &testObserver{}
	p.observer = observer
	require.NoError(t, p.Start())
	t.Cleanup(func() { require.NoError(t, p.Stop()) })
	msg := &pp.PexRequest{}
	// A full local queue is not a completed response and must emit no event.
	require.False(t, p.send(testCh, msg, func(byte, []byte) bool { return false }))
	require.Empty(t, observer.snapshot())
	var size int
	require.True(t, p.send(testCh, msg, func(_ byte, b []byte) bool { size = len(b); return true }))
	events := observer.snapshot()
	require.Len(t, events, 1)
	require.Equal(t, string(rp.ID()), events[0].id)
	require.Equal(t, observation.Queued, events[0].event.Kind)
	require.Equal(t, byte(testCh), events[0].event.Channel)
	require.Equal(t, size, events[0].event.Bytes)
	require.IsType(t, msg, events[0].event.Message) // unwrapped original, not wire wrapper
	require.False(t, p.send(0xff, msg, func(byte, []byte) bool { t.Fatal("unknown channel sent"); return true }))
	require.Len(t, observer.snapshot(), 1)
}

func TestPeerObservationNativeTransport(t *testing.T) {
	for _, outbound := range []bool{false, true} {
		t.Run(map[bool]string{false: "inbound", true: "outbound"}[outbound], func(t *testing.T) {
			observer := &testObserver{}
			config := config.DefaultP2PConfig()
			config.PeerObserver = observer
			sw := MakeSwitch(config, 1, initSwitchFunc)
			require.NoError(t, sw.Start())
			t.Cleanup(func() { require.NoError(t, sw.Stop()) })
			rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: config}
			rp.Start()
			t.Cleanup(rp.Stop)
			if outbound {
				require.NoError(t, sw.DialPeerWithAddress(rp.Addr()))
			} else {
				c, err := rp.Dial(sw.NetAddress())
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, c.Close()) })
			}
			require.Eventually(t, func() bool { return sw.Peers().Get(rp.ID()) != nil }, time.Second, 10*time.Millisecond)
			peer := sw.Peers().Get(rp.ID())
			sw.ObserveInvalid(peer, testCh)
			require.True(t, peer.Send(Envelope{ChannelID: testCh, Message: &pp.PexRequest{}}))
			events := observer.snapshot()
			require.Len(t, events, 2)
			require.Equal(t, observation.InvalidMessage, events[0].event.Kind)
			require.Equal(t, string(rp.ID()), events[0].id)
			require.Equal(t, byte(testCh), events[0].event.Channel)
			require.Equal(t, observation.Queued, events[1].event.Kind)
		})
	}
}

func TestPeerObservationDisabled(t *testing.T) {
	// Nil observers must return before even resolving the peer identity.
	(&peer{}).observe(observation.Event{})
	var sw *Switch
	sw.ObserveInvalid(nil, 0)
	(&Switch{config: config.DefaultP2PConfig()}).ObserveInvalid(nil, 0)
}

func observedSwitch(t *testing.T, observer observation.Observer) *Switch {
	t.Helper()
	conf := config.DefaultP2PConfig()
	conf.PeerObserver = observer
	sw := MakeSwitch(conf, 1, initSwitchFunc)
	ni := sw.NodeInfo().(DefaultNodeInfo)
	ni.Channels = []byte{0, 1, 2, 3}
	sw.SetNodeInfo(ni)
	sw.transport.(*MultiplexTransport).nodeInfo = ni
	require.NoError(t, sw.Start())
	t.Cleanup(func() { require.NoError(t, sw.Stop()) })
	return sw
}

func TestPeerObservationReceive(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
		kind observation.Kind
	}{
		{"valid", []byte{0x0a, 0}, observation.Received},
		{"decode-failure", []byte{0xff}, observation.InvalidEncoding},
		{"unwrap-failure", []byte{}, observation.InvalidEncoding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observer := &testObserver{}
			receiver := observedSwitch(t, observer)
			sender := observedSwitch(t, nil)
			require.NoError(t, sender.DialPeerWithAddress(receiver.NetAddress()))
			peer := sender.Peers().Get(receiver.NodeInfo().ID()).(*peer)
			require.True(t, peer.mconn.Send(testCh, tc.raw))
			require.Eventually(t, func() bool { return len(observer.snapshot()) == 1 }, 2*time.Second, 10*time.Millisecond)
			event := observer.snapshot()[0]
			require.Equal(t, string(sender.NodeInfo().ID()), event.id)
			require.Equal(t, tc.kind, event.event.Kind)
			require.Equal(t, byte(testCh), event.event.Channel)
			require.Equal(t, len(tc.raw), event.event.Bytes)
			if tc.kind == observation.Received {
				require.IsType(t, &pp.PexRequest{}, event.event.Message)
				require.Eventually(t, func() bool { return len(receiver.Reactor("foo").(*TestReactor).getMsgs(testCh)) == 1 }, time.Second, 10*time.Millisecond)
			} else {
				require.Nil(t, event.event.Message)
				require.Eventually(t, func() bool { return receiver.Peers().Size() == 0 }, time.Second, 10*time.Millisecond)
			}
		})
	}
}
