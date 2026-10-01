package blocksync

import (
	"github.com/cometbft/cometbft/types"
	"github.com/go-kit/kit/metrics"
)

const (
	// MetricsSubsystem is a subsystem shared by all metrics exposed by this
	// package.
	MetricsSubsystem = "blocksync"
)

//go:generate go run ../scripts/metricsgen -struct=Metrics

// Metrics contains metrics exposed by this package.
type Metrics struct {
	// Whether or not a node is block syncing. 1 if yes, 0 if no.
	Syncing metrics.Gauge
	// Number of transactions in the latest block.
	NumTxs metrics.Gauge
	// Total number of transactions.
	TotalTxs metrics.Gauge
	// Size of the latest block.
	BlockSizeBytes metrics.Gauge
	// The height of the latest block.
	LatestBlockHeight metrics.Gauge
	// Total number of BlockRequest messages dropped for exceeding a peer's
	// block-sync request rate limit.
	PeerBlockRequestsDropped metrics.Counter
	// Current number of peer identities with a tracked block-sync request
	// window. Sampled post-sweep, so this reflects steady-state map size
	// rather than a transient peak.
	PeerLimiterWindows metrics.Gauge
	// Current number of peer identities banned for exceeding their
	// block-sync request window. Sampled post-sweep.
	PeerLimiterBans metrics.Gauge
	// Total number of BlockRequest messages dropped for exceeding a remote
	// subnet's (see ipRateLimitKey) block-sync request rate limit.
	SubnetBlockRequestsDropped metrics.Counter
	// Current number of remote subnets with a tracked block-sync request
	// window. Sampled post-sweep.
	SubnetLimiterWindows metrics.Gauge
	// Current number of remote subnets banned for exceeding their
	// block-sync request window. Sampled post-sweep.
	SubnetLimiterBans metrics.Gauge
	// Total number of BlockRequest messages served to a persistent peer
	// (see IsPersistent) without either rate limiter applied.
	PersistentPeerRequestsExempted metrics.Counter
	// Total bytes of BlockResponse handed to the transport, counting the
	// block, its extended commit and envelope overhead.
	BlockBytesServed metrics.Counter
	// Total number of BlockRequest messages dropped because the node-wide
	// serving budget, a remote subnet's share of it, or a remote address's
	// rolling byte quota was exhausted.
	ServingBudgetDrops metrics.Counter
	// Bytes currently available in the node-wide serving budget. Sampled
	// post-sweep. Negative while the budget is repaying an under-estimated
	// response.
	ServingBudgetTokens metrics.Gauge
	// Current number of remote subnets with a tracked serving-budget
	// share. Sampled post-sweep.
	ServingSubnetBudgets metrics.Gauge
	// Current number of remote addresses with a tracked byte quota.
	// Sampled post-sweep.
	ServingPeerQuotas metrics.Gauge
}

func (m *Metrics) recordBlockMetrics(block *types.Block) {
	m.NumTxs.Set(float64(len(block.Txs)))
	m.TotalTxs.Add(float64(len(block.Txs)))
	m.BlockSizeBytes.Set(float64(block.Size()))
	m.LatestBlockHeight.Set(float64(block.Height))
}
