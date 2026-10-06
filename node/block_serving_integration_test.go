package node

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/abci/example/kvstore"
	"github.com/cometbft/cometbft/blocksync"
	"github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	p2pmock "github.com/cometbft/cometbft/p2p/mock"
	"github.com/cometbft/cometbft/privval"
	bcproto "github.com/cometbft/cometbft/proto/tendermint/blocksync"
	"github.com/cometbft/cometbft/proxy"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
	"github.com/cometbft/cometbft/types"
)

func TestNativeBlockServingQueueMetrics(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		enabled bool
	}{
		{"enabled", true},
		{"disabled", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.TestConfig()
			cfg.Instrumentation.Prometheus = tc.enabled
			cfg.Instrumentation.Namespace = "block_serving_test_" + tc.name
			metricName := cfg.Instrumentation.Namespace + "_blocksync_send_queue_full_drops"
			collector := stdprometheus.NewCounterVec(stdprometheus.CounterOpts{
				Name: metricName, Help: "Block requests dropped because the peer's send queue is full.",
			}, []string{"chain_id"})
			t.Cleanup(func() { require.Equal(t, tc.enabled, stdprometheus.Unregister(collector)) })
			state := sm.State{ChainID: "queue-test-chain", InitialHeight: 1,
				Validators: &types.ValidatorSet{}, NextValidators: &types.ValidatorSet{}, LastValidators: &types.ValidatorSet{}}
			reactor, err := createBlocksyncReactor(cfg, state, nil, &store.BlockStore{}, false, nil,
				log.NewNopLogger(), blocksync.NopMetrics(), 0)
			require.NoError(t, err)
			peer := &fullBlockServingPeer{Peer: p2pmock.NewPeer(nil)}
			t.Cleanup(func() { require.NoError(t, peer.Stop()) })
			request := p2p.Envelope{Src: peer, Message: &bcproto.BlockRequest{Height: 1}}
			reactor.Receive(request)
			reactor.Receive(request)
			requireBlockServingQueueMetric(t, metricName, tc.enabled)
		})
	}
}

func requireBlockServingQueueMetric(t *testing.T, name string, enabled bool) {
	t.Helper()
	families, err := stdprometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		require.True(t, enabled)
		require.Equal(t, "COUNTER", family.GetType().String())
		require.Len(t, family.Metric, 1)
		metric := family.Metric[0]
		require.Equal(t, float64(2), metric.GetCounter().GetValue())
		require.Len(t, metric.Label, 1)
		require.Equal(t, "chain_id", metric.Label[0].GetName())
		require.Equal(t, "queue-test-chain", metric.Label[0].GetValue())
		return
	}
	require.False(t, enabled, "missing metric %s", name)
}

type fullBlockServingPeer struct{ p2p.Peer }

func (*fullBlockServingPeer) SendQueueFull(chID byte) bool {
	return chID == blocksync.BlocksyncChannel
}

func TestNativeBlockServingPeerCatchesUp(t *testing.T) {
	t.Parallel()
	key := ed25519.GenPrivKey()
	genesis := &types.GenesisDoc{
		GenesisTime: time.Now(), ChainID: "block-serving-test", InitialHeight: 1,
		ConsensusParams: types.DefaultConsensusParams(),
		Validators:      []types.GenesisValidator{{PubKey: key.PubKey(), Power: 10}},
	}
	server := newBlockServingNode(t, key, genesis)
	require.IsType(t, &blocksync.Reactor{}, server.Switch().Reactor("BLOCKSYNC"))
	waitForBlockServingHeight(t, server, 5)
	require.True(t, server.Switch().Reactor("BLOCKSYNC").IsRunning())
	client := newBlockServingNode(t, ed25519.GenPrivKey(), genesis)
	require.IsType(t, &blocksync.Reactor{}, client.Switch().Reactor("BLOCKSYNC"))
	require.NoError(t, client.Switch().DialPeerWithAddress(server.Switch().NetAddress()))
	waitForBlockServingHeight(t, client, 5)
	require.Equal(t, server.BlockStore().LoadBlock(5).Hash(), client.BlockStore().LoadBlock(5).Hash())
}

func newBlockServingNode(t *testing.T, key ed25519.PrivKey, genesis *types.GenesisDoc) *Node {
	t.Helper()
	cfg := config.TestConfig().SetRoot(t.TempDir())
	cfg.RPC.ListenAddress = ""
	cfg.P2P.ListenAddress = "tcp://" + testFreeAddr(t)
	cfg.P2P.PexReactor = false
	for _, dir := range []string{"config", "data"} {
		require.NoError(t, os.MkdirAll(filepath.Join(cfg.RootDir, dir), 0o700))
	}
	pv := privval.NewFilePV(key, cfg.PrivValidatorKeyFile(), cfg.PrivValidatorStateFile())
	genesisProvider := func() (*types.GenesisDoc, error) { return genesis, nil }
	n, err := NewNodeWithContext(context.Background(), cfg, pv,
		&p2p.NodeKey{PrivKey: ed25519.GenPrivKey()}, proxy.NewLocalClientCreator(kvstore.NewInMemoryApplication()),
		genesisProvider, config.DefaultDBProvider, DefaultMetricsProvider(cfg.Instrumentation), log.NewNopLogger())
	require.NoError(t, err)
	require.NoError(t, n.Start())
	t.Cleanup(func() {
		require.NoError(t, n.Stop())
		n.Wait()
		require.False(t, n.Switch().Reactor("BLOCKSYNC").IsRunning())
	})
	return n
}

func waitForBlockServingHeight(t *testing.T, n *Node, height int64) {
	t.Helper()
	require.Eventually(t, func() bool { return n.BlockStore().Height() >= height }, 15*time.Second, 10*time.Millisecond,
		"node did not reach height %d", height)
}
