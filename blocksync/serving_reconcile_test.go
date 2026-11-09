package blocksync

import (
	"bytes"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/internal/test"
	"github.com/cometbft/cometbft/libs/log"
	bcproto "github.com/cometbft/cometbft/proto/tendermint/blocksync"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

// A request refused for size must be refused before the block is loaded; once
// loaded, the full response is charged, so a peer cannot repeat that work for
// free while the budget sits just below one response.
func TestRespondToPeerChargesOrSkipsUnaffordableWork(t *testing.T) {
	for _, tc := range []struct {
		name              string
		txBytes, extBytes int
		burst             func(blockSize, served float64) float64
		queued, skipsLoad bool
		charged           func(blockSize, served float64) float64
	}{
		{
			name: "response that exactly fits the burst is served", txBytes: 900 << 10, extBytes: 1 << 10,
			burst:   func(_, served float64) float64 { return served },
			queued:  true,
			charged: func(_, served float64) float64 { return served },
		},
		{
			name: "oversized block is refused before loading", txBytes: 900 << 10, extBytes: 1 << 10,
			burst:     func(float64, float64) float64 { return 2 * estimatedResponseBytes },
			skipsLoad: true,
			charged:   func(float64, float64) float64 { return 0 },
		},
		{
			name: "block one byte over the burst with its overhead is refused before loading", txBytes: 900 << 10, extBytes: 1 << 10,
			burst:     func(blockSize, _ float64) float64 { return blockSize + blockResponseOverheadBytes - 1 },
			skipsLoad: true,
			charged:   func(float64, float64) float64 { return 0 },
		},
		{
			name: "response under the estimate is refunded to its real size", txBytes: 1 << 10, extBytes: 1 << 10,
			burst:   func(float64, float64) float64 { return 2 * estimatedResponseBytes },
			queued:  true,
			charged: func(_, served float64) float64 { return served },
		},
		{
			name: "extended commit beyond the burst is served and carried as debt", txBytes: 1 << 10, extBytes: 2 * estimatedResponseBytes,
			burst:   func(float64, float64) float64 { return estimatedResponseBytes },
			queued:  true,
			charged: func(_, served float64) float64 { return served },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newSingleBlockReactor(t, tc.txBytes, tc.extBytes)
			blockSize := float64(r.store.LoadBlockMeta(1).BlockSize)
			extCommit, ok := r.loadExtCommit(1)
			require.True(t, ok)
			served := blockSize + float64(extCommit.Size()+blockResponseOverheadBytes)

			burst := tc.burst(blockSize, served)
			r.servingBudget = newServingBudget(ServingConfig{Rate: 1e-9, Burst: burst})
			peer := newBlockServingPeer(t, false)

			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			require.Equal(t, tc.queued, r.respondToPeer(&bcproto.BlockRequest{Height: 1}, peer))
			runtime.ReadMemStats(&after)

			require.InDelta(t, burst-tc.charged(blockSize, served), r.servingBudget.globalAvailable(), 1)
			if tc.skipsLoad {
				require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(blockSize))
			}
		})
	}
}

// A peer whose response overshot its quota is refused until refill repays the
// debt and covers a fresh estimate, and is then served again.
func TestRespondToPeerRefusesWhileInDebt(t *testing.T) {
	r := newSingleBlockReactor(t, 1<<10, 2*estimatedResponseBytes)
	extCommit, ok := r.loadExtCommit(1)
	require.True(t, ok)
	served := float64(r.store.LoadBlockMeta(1).BlockSize + extCommit.Size() + blockResponseOverheadBytes)

	// One byte per second, so the test's own runtime adds no measurable refill.
	r.servingBudget = newServingBudget(ServingConfig{
		Quota: estimatedResponseBytes, QuotaPeriod: estimatedResponseBytes * time.Second,
	})
	peer := newBlockServingPeer(t, false)
	quota := r.servingBudget.quotas.get(peer.RemoteIP().String())
	request := func() bool { return r.respondToPeer(&bcproto.BlockRequest{Height: 1}, peer) }

	require.True(t, request())
	debt := served - estimatedResponseBytes
	require.InDelta(t, -debt, quota.available(), 1)

	require.False(t, request(), "refused while in debt")
	require.InDelta(t, -debt, quota.available(), 1, "a refused request is not charged")

	elapse := func(d time.Duration) {
		quota.mtx.Lock()
		quota.last = quota.last.Add(-d)
		quota.mtx.Unlock()
	}
	elapse(time.Duration(debt) * time.Second)
	require.False(t, request(), "back at zero, but a fresh estimate is not yet covered")

	elapse(estimatedResponseBytes*time.Second + time.Second)
	require.True(t, request(), "served again once refill covers the estimate")
	require.InDelta(t, -debt, quota.available(), 1, "charged in full again")
}

func newSingleBlockReactor(t *testing.T, txBytes, extBytes int) *Reactor {
	t.Helper()
	config = test.ResetTestRoot("blocksync_serving_reconcile_test")
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(config.RootDir)) })

	genDoc, privVals := genesisDocWithValsPowers([]int64{30})
	pair := newReactor(t, log.NewNopLogger(), genDoc, privVals, 0)
	t.Cleanup(func() { require.NoError(t, pair.app.Stop()) })
	r := pair.reactor.Reactor

	state, err := r.blockExec.Store().Load()
	require.NoError(t, err)
	block, err := state.MakeBlock(1, []types.Tx{bytes.Repeat([]byte{1}, txBytes)},
		(&types.ExtendedCommit{}).ToCommit(), nil, state.Validators.Proposer.Address)
	require.NoError(t, err)
	parts, err := block.MakePartSet(types.PartSizeBytes)
	require.NoError(t, err)
	blockID := types.BlockID{Hash: block.Hash(), PartSetHeader: parts.Header()}

	vote, err := types.MakeVote(privVals[0], block.ChainID, 0, 1, 0, cmtproto.PrecommitType, blockID, time.Now())
	require.NoError(t, err)
	sig := vote.ExtendedCommitSig()
	sig.Extension = bytes.Repeat([]byte{2}, extBytes)
	r.store.SaveBlockWithExtendedCommit(block, parts, &types.ExtendedCommit{
		Height: 1, BlockID: blockID, ExtendedSignatures: []types.ExtendedCommitSig{sig},
	})
	return r
}
