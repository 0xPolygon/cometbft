package p2p

import (
	"fmt"
	golog "log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/bytes"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/proto/tendermint/p2p"

	"github.com/cometbft/cometbft/config"
	cmtconn "github.com/cometbft/cometbft/p2p/conn"
)

func TestPeerBasic(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	// simulate remote peer
	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	rp.Start()
	t.Cleanup(rp.Stop)

	p, err := createOutboundPeerAndPerformHandshake(rp.Addr(), cfg, cmtconn.DefaultMConnConfig())
	require.Nil(err)

	err = p.Start()
	require.Nil(err)
	t.Cleanup(func() {
		if err := p.Stop(); err != nil {
			t.Error(err)
		}
	})

	assert.True(p.IsRunning())
	assert.True(p.IsOutbound())

	// RemoteIP caches on *peer (not peerConn — see ipOnce's doc comment
	// for why) so this cache write must actually persist to p.ip.
	ip1 := p.RemoteIP()
	require.NotNil(ip1)
	require.NotNil(p.ip, "RemoteIP's first call must populate the cache field")
	ip2 := p.RemoteIP()
	assert.True(ip1.Equal(ip2))
	assert.False(p.IsPersistent())
	p.persistent = true
	assert.True(p.IsPersistent())
	assert.Equal(rp.Addr().DialString(), p.RemoteAddr().String())
	assert.Equal(rp.ID(), p.ID())
}

// TestPeerRemoteIPConcurrentFirstCall proves RemoteIP's cache populate is
// safe when multiple goroutines race to resolve it for the first time —
// the shape of the actual concurrent callers in this codebase (this
// reactor's own receive path, the RPC net_info handler, PeerSet.hasIP).
// Before ipOnce, a bare nil-check-then-write here was a genuine data race
// under -race, not just a theoretical one.
func TestPeerRemoteIPConcurrentFirstCall(t *testing.T) {
	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
	rp.Start()
	t.Cleanup(rp.Stop)

	p, err := createOutboundPeerAndPerformHandshake(rp.Addr(), cfg, cmtconn.DefaultMConnConfig())
	require.NoError(t, err)
	require.NoError(t, p.Start())
	t.Cleanup(func() {
		_ = p.Stop()
	})

	const concurrency = 50
	results := make([]net.IP, concurrency)
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := range concurrency {
		go func() {
			defer wg.Done()
			results[i] = p.RemoteIP()
		}()
	}
	wg.Wait()

	for _, ip := range results {
		require.True(t, results[0].Equal(ip), "every concurrent caller must observe the same resolved IP")
	}
}

func TestPeerSend(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	config := cfg

	// simulate remote peer
	rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: config}
	rp.Start()
	t.Cleanup(rp.Stop)

	p, err := createOutboundPeerAndPerformHandshake(rp.Addr(), config, cmtconn.DefaultMConnConfig())
	require.Nil(err)

	err = p.Start()
	require.Nil(err)

	t.Cleanup(func() {
		if err := p.Stop(); err != nil {
			t.Error(err)
		}
	})

	assert.True(p.CanSend(testCh))
	assert.True(p.Send(Envelope{ChannelID: testCh, Message: &p2p.Message{}}))
}

func createOutboundPeerAndPerformHandshake(
	addr *NetAddress,
	config *config.P2PConfig,
	mConfig cmtconn.MConnConfig,
) (*peer, error) {
	chDescs := []*cmtconn.ChannelDescriptor{
		{ID: testCh, Priority: 1},
	}
	reactorsByCh := map[byte]Reactor{testCh: NewTestReactor(chDescs, true)}
	msgTypeByChID := map[byte]proto.Message{
		testCh: &p2p.Message{},
	}
	pk := ed25519.GenPrivKey()
	pc, err := testOutboundPeerConn(addr, config, false, pk)
	if err != nil {
		return nil, err
	}
	timeout := 1 * time.Second
	ourNodeInfo := testNodeInfo(addr.ID, "host_peer")
	peerNodeInfo, err := handshake(pc.conn, timeout, ourNodeInfo)
	if err != nil {
		return nil, err
	}

	p := newPeer(pc, mConfig, peerNodeInfo, reactorsByCh, msgTypeByChID, chDescs, func(p Peer, r interface{}) {}, newMetricsLabelCache())
	p.SetLogger(log.TestingLogger().With("peer", addr))
	return p, nil
}

func testDial(addr *NetAddress, cfg *config.P2PConfig) (net.Conn, error) {
	if cfg.TestDialFail {
		return nil, fmt.Errorf("dial err (peerConfig.DialFail == true)")
	}

	conn, err := addr.DialTimeout(cfg.DialTimeout)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func testOutboundPeerConn(
	addr *NetAddress,
	config *config.P2PConfig,
	persistent bool,
	ourNodePrivKey crypto.PrivKey,
) (peerConn, error) {

	var pc peerConn
	conn, err := testDial(addr, config)
	if err != nil {
		return pc, fmt.Errorf("error creating peer: %w", err)
	}

	pc, err = testPeerConn(conn, config, true, persistent, ourNodePrivKey, addr)
	if err != nil {
		if cerr := conn.Close(); cerr != nil {
			return pc, fmt.Errorf("%v: %w", cerr.Error(), err)
		}
		return pc, err
	}

	// ensure dialed ID matches connection ID
	if addr.ID != pc.ID() {
		if cerr := conn.Close(); cerr != nil {
			return pc, fmt.Errorf("%v: %w", cerr.Error(), err)
		}
		return pc, ErrSwitchAuthenticationFailure{addr, pc.ID()}
	}

	return pc, nil
}

type remotePeer struct {
	PrivKey    crypto.PrivKey
	Config     *config.P2PConfig
	addr       *NetAddress
	channels   bytes.HexBytes
	listenAddr string
	listener   net.Listener
}

func (rp *remotePeer) Addr() *NetAddress {
	return rp.addr
}

func (rp *remotePeer) ID() ID {
	return PubKeyToID(rp.PrivKey.PubKey())
}

func (rp *remotePeer) Start() {
	if rp.listenAddr == "" {
		rp.listenAddr = "127.0.0.1:0"
	}

	l, e := net.Listen("tcp", rp.listenAddr) // any available address
	if e != nil {
		golog.Fatalf("net.Listen tcp :0: %+v", e)
	}
	rp.listener = l
	rp.addr = NewNetAddress(PubKeyToID(rp.PrivKey.PubKey()), l.Addr())
	if rp.channels == nil {
		rp.channels = []byte{testCh}
	}
	go rp.accept()
}

func (rp *remotePeer) Stop() {
	rp.listener.Close()
}

func (rp *remotePeer) Dial(addr *NetAddress) (net.Conn, error) {
	conn, err := addr.DialTimeout(1 * time.Second)
	if err != nil {
		return nil, err
	}
	pc, err := testInboundPeerConn(conn, rp.Config, rp.PrivKey)
	if err != nil {
		return nil, err
	}
	_, err = handshake(pc.conn, time.Second, rp.nodeInfo())
	if err != nil {
		return nil, err
	}
	return conn, err
}

func (rp *remotePeer) accept() {
	conns := []net.Conn{}

	for {
		conn, err := rp.listener.Accept()
		if err != nil {
			golog.Printf("Failed to accept conn: %+v", err)
			for _, conn := range conns {
				_ = conn.Close()
			}
			return
		}

		pc, err := testInboundPeerConn(conn, rp.Config, rp.PrivKey)
		if err != nil {
			golog.Fatalf("Failed to create a peer: %+v", err)
		}

		_, err = handshake(pc.conn, time.Second, rp.nodeInfo())
		if err != nil {
			golog.Fatalf("Failed to perform handshake: %+v", err)
		}

		conns = append(conns, conn)
	}
}

func (rp *remotePeer) nodeInfo() NodeInfo {
	return DefaultNodeInfo{
		ProtocolVersion: defaultProtocolVersion,
		DefaultNodeID:   rp.Addr().ID,
		ListenAddr:      rp.listener.Addr().String(),
		Network:         "testing",
		Version:         "1.2.3-rc0-deadbeef",
		Channels:        rp.channels,
		Moniker:         "remote_peer",
	}
}
