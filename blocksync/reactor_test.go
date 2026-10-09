package blocksync

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	bcproto "github.com/cometbft/cometbft/proto/tendermint/blocksync"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	dbm "github.com/cometbft/cometbft-db"

	abci "github.com/cometbft/cometbft/abci/types"
	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/internal/test"
	"github.com/cometbft/cometbft/libs/log"
	mpmocks "github.com/cometbft/cometbft/mempool/mocks"
	"github.com/cometbft/cometbft/p2p"
	p2pmock "github.com/cometbft/cometbft/p2p/mock"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/proxy"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
	"github.com/cometbft/cometbft/types"
	cmttime "github.com/cometbft/cometbft/types/time"
)

var config *cfg.Config

func genesisDocWithValsPowers(powers []int64) (*types.GenesisDoc, []types.PrivValidator) {
	if len(powers) == 0 {
		panic("must have atleast 1 validator")
	}

	validators := make([]types.GenesisValidator, len(powers))
	privValidators := make([]types.PrivValidator, len(powers))
	for i, power := range powers {
		val, privVal := types.RandValidator(false, power)
		validators[i] = types.GenesisValidator{
			PubKey: val.PubKey,
			Power:  val.VotingPower,
		}
		privValidators[i] = privVal
	}
	sort.Sort(types.PrivValidatorsByAddress(privValidators))

	consPar := types.DefaultConsensusParams()
	consPar.ABCI.VoteExtensionsEnableHeight = 1
	return &types.GenesisDoc{
		GenesisTime:     cmttime.Now(),
		ChainID:         test.DefaultTestChainID,
		Validators:      validators,
		ConsensusParams: consPar,
	}, privValidators
}

type ReactorPair struct {
	reactor *ByzantineReactor
	app     proxy.AppConns
}

type reactorOpts struct {
	corruptedBlock          int64
	allAbsentExtCommitBlock int64
	invalidExtCommitBlock   int64
	deterministicVoteTimes  bool
}

type reactorOption func(*reactorOpts)

func withCorruptedBlock(height int64) reactorOption {
	return func(o *reactorOpts) {
		o.corruptedBlock = height
	}
}

func withAllAbsentExtCommitBlock(height int64) reactorOption {
	return func(o *reactorOpts) {
		o.allAbsentExtCommitBlock = height
	}
}

func withInvalidExtCommitBlock(height int64) reactorOption {
	return func(o *reactorOpts) {
		o.invalidExtCommitBlock = height
	}
}

func newReactor(
	t *testing.T,
	logger log.Logger,
	genDoc *types.GenesisDoc,
	privVals []types.PrivValidator,
	maxBlockHeight int64,
	opts ...reactorOption,
) ReactorPair {

	var options reactorOpts
	for _, opt := range opts {
		opt(&options)
	}

	app := abci.NewBaseApplication()
	cc := proxy.NewLocalClientCreator(app)
	proxyApp := proxy.NewAppConns(cc, proxy.NopMetrics())
	err := proxyApp.Start()
	if err != nil {
		panic(fmt.Errorf("error start app: %w", err))
	}

	blockDB := dbm.NewMemDB()
	stateDB := dbm.NewMemDB()
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{
		DiscardABCIResponses: false,
	})
	blockStore := store.NewBlockStore(blockDB)

	state, err := stateStore.LoadFromDBOrGenesisDoc(genDoc)
	if err != nil {
		panic(fmt.Errorf("error constructing state from genesis file: %w", err))
	}

	mp := &mpmocks.Mempool{}
	mp.On("Lock").Return()
	mp.On("Unlock").Return()
	mp.On("FlushAppConn", mock.Anything).Return(nil)
	mp.On("Update",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything).Return(nil)

	// Make the Reactor itself.
	// NOTE we have to create and commit the blocks first because
	// pool.height is determined from the store.
	blockSync := true
	db := dbm.NewMemDB()
	stateStore = sm.NewStore(db, sm.StoreOptions{
		DiscardABCIResponses: false,
	})
	blockExec := sm.NewBlockExecutor(stateStore, log.TestingLogger(), proxyApp.Consensus(),
		mp, sm.EmptyEvidencePool{}, blockStore)
	if err = stateStore.Save(state); err != nil {
		panic(err)
	}

	// The commit we are building for the current height.
	seenExtCommit := &types.ExtendedCommit{}

	// let's add some blocks in
	for blockHeight := int64(1); blockHeight <= maxBlockHeight; blockHeight++ {
		voteExtensionIsEnabled := genDoc.ConsensusParams.ABCI.VoteExtensionsEnabled(blockHeight)

		lastExtCommit := seenExtCommit.Clone()

		thisBlock, err := state.MakeBlock(blockHeight, nil, lastExtCommit.ToCommit(), nil, state.Validators.Proposer.Address)
		require.NoError(t, err)

		thisParts, err := thisBlock.MakePartSet(types.PartSizeBytes)
		require.NoError(t, err)
		blockID := types.BlockID{Hash: thisBlock.Hash(), PartSetHeader: thisParts.Header()}

		voteTime := time.Now()
		if options.deterministicVoteTimes {
			// use deterministic vote times so independently constructed test chains
			// with the same genesis produce identical block IDs and LastBlockID links.
			voteTime = genDoc.GenesisTime.Add(time.Duration(blockHeight) * time.Second)
		}

		// Simulate commits for the current height
		extCommit := make([]types.ExtendedCommitSig, len(privVals))
		for _, val := range privVals {
			pubKey, err := val.GetPubKey()
			if err != nil {
				panic(err)
			}
			addr := pubKey.Address()
			idx, _ := state.Validators.GetByAddress(addr)

			vote, err := types.MakeVote(val, thisBlock.ChainID, idx, thisBlock.Height, 0, cmtproto.PrecommitType, blockID, voteTime)
			if err != nil {
				panic(err)
			}
			extCommit[idx] = vote.ExtendedCommitSig()
		}
		seenExtCommit = &types.ExtendedCommit{
			Height:             thisBlock.Height,
			Round:              0,
			BlockID:            blockID,
			ExtendedSignatures: extCommit,
		}

		state, err = blockExec.ApplyBlock(state, blockID, thisBlock)
		if err != nil {
			panic(fmt.Errorf("error apply block: %w", err))
		}

		saveCorrectVoteExtensions := blockHeight != options.corruptedBlock
		if saveCorrectVoteExtensions == voteExtensionIsEnabled {
			blockStore.SaveBlockWithExtendedCommit(thisBlock, thisParts, seenExtCommit)
		} else {
			blockStore.SaveBlock(thisBlock, thisParts, seenExtCommit.ToCommit())
		}
	}

	bcReactor := NewByzantineReactor(NewReactor(state.Copy(), blockExec, blockStore, blockSync, NopMetrics(), 0))
	bcReactor.corruptedBlock = options.corruptedBlock
	bcReactor.absentExtCommitBlock = options.allAbsentExtCommitBlock
	bcReactor.invalidExtCommitBlock = options.invalidExtCommitBlock
	bcReactor.SetLogger(logger.With("module", "blocksync"))

	return ReactorPair{bcReactor, proxyApp}
}

func TestNoBlockResponse(t *testing.T) {
	config = test.ResetTestRoot("blocksync_reactor_test")
	defer os.RemoveAll(config.RootDir)
	genDoc, privVals := genesisDocWithValsPowers([]int64{30})

	maxBlockHeight := int64(65)

	reactorPairs := make([]ReactorPair, 2)

	reactorPairs[0] = newReactor(t, log.TestingLogger(), genDoc, privVals, maxBlockHeight)
	reactorPairs[1] = newReactor(t, log.TestingLogger(), genDoc, privVals, 0)

	p2p.MakeConnectedSwitches(config.P2P, 2, func(i int, s *p2p.Switch) *p2p.Switch {
		s.AddReactor("BLOCKSYNC", reactorPairs[i].reactor)
		return s
	}, p2p.Connect2Switches)

	defer func() {
		for _, r := range reactorPairs {
			_ = r.reactor.Stop()
			// require.NoError(t, err)
			_ = r.app.Stop()
			// require.NoError(t, err)
		}
	}()

	tests := []struct {
		height   int64
		existent bool
	}{
		{maxBlockHeight + 2, false},
		{10, true},
		{1, true},
		{100, false},
	}

	for !reactorPairs[1].reactor.pool.IsCaughtUp() {

		time.Sleep(10 * time.Millisecond)
	}

	assert.Equal(t, maxBlockHeight, reactorPairs[0].reactor.store.Height())

	for _, tt := range tests {
		block := reactorPairs[1].reactor.store.LoadBlock(tt.height)
		if tt.existent {
			assert.True(t, block != nil)
		} else {
			assert.True(t, block == nil)
		}
	}
}

// TestRespondToPeer_RateLimitsBlockRequests exercises the production
// (*Reactor).respondToPeer directly via the embedded field, rather than
// through ByzantineReactor's shadowing override — every other test in this
// file goes through ByzantineReactor.respondToPeer, a separate hand-copied
// method, so the real one (where the rate limiter and the LoadBlockProto
// fast path actually live) was otherwise never exercised by this suite.
func TestRespondToPeer_RateLimitsBlockRequests(t *testing.T) {
	config = test.ResetTestRoot("blocksync_reactor_test")
	defer os.RemoveAll(config.RootDir)
	genDoc, privVals := genesisDocWithValsPowers([]int64{30})

	pair := newReactor(t, log.TestingLogger(), genDoc, privVals, 5)
	// respondToPeer is called directly below, without starting the reactor's
	// pool/blockSync goroutines, so there's nothing to Stop() on the reactor
	// itself — only the proxy app needs tearing down.
	defer func() {
		_ = pair.app.Stop()
	}()

	peer := p2pmock.NewPeer(nil)
	defer peer.Stop() //nolint:errcheck

	msg := &bcproto.BlockRequest{Height: 1}

	for i := 0; i < maxBlockRequestsPerWindow; i++ {
		queued := pair.reactor.Reactor.respondToPeer(msg, peer)
		require.True(t, queued, "request %d within the per-window limit should be served", i)
	}

	queued := pair.reactor.Reactor.respondToPeer(msg, peer)
	require.False(t, queued, "request beyond the per-window limit should be dropped")
}

// TestRespondToPeer_ExactCapReconnectDoesNotResetWindow proves that a peer
// which disconnects right at the cap — without ever sending the request
// that would exceed it — can't get a fresh window by reconnecting. RemovePeer
// (the real disconnect path) doesn't touch reqLimiter at all: window state
// is only ever cleared by natural time-based expiry, never by disconnect.
// Without this, a peer could sustain far more than maxBlockRequestsPerWindow
// by sending exactly up to the cap, disconnecting before tripping a ban,
// and reconnecting immediately for a new window — never actually banned,
// but never throttled either.
func TestRespondToPeer_ExactCapReconnectDoesNotResetWindow(t *testing.T) {
	config = test.ResetTestRoot("blocksync_reactor_test")
	defer os.RemoveAll(config.RootDir)
	genDoc, privVals := genesisDocWithValsPowers([]int64{30})

	pair := newReactor(t, log.TestingLogger(), genDoc, privVals, 5)
	defer func() {
		_ = pair.app.Stop()
	}()

	peer := p2pmock.NewPeer(nil)
	defer peer.Stop() //nolint:errcheck

	msg := &bcproto.BlockRequest{Height: 1}

	for i := 0; i < maxBlockRequestsPerWindow; i++ {
		queued := pair.reactor.Reactor.respondToPeer(msg, peer)
		require.True(t, queued, "request %d within the per-window limit should be served", i)
	}

	// Disconnect and reconnect with the same identity while sitting exactly
	// at the cap, without ever having sent an over-limit request.
	pair.reactor.RemovePeer(peer, nil)

	queued := pair.reactor.Reactor.respondToPeer(msg, peer)
	require.False(t, queued, "a peer that used its full window before disconnecting must not get a fresh window on reconnect")
}

// TestRespondToPeer_IPLimiterCapsAcrossDistinctIdentities proves the
// per-identity limiter alone isn't the whole story: a source that mints a
// fresh p2p.ID for every connection (free — a local keypair, no ban/window
// history) still gets capped once enough distinct identities from the same
// remote IP have collectively used up the IP-level budget, even though no
// single identity here ever exceeds its own per-identity window.
func TestRespondToPeer_IPLimiterCapsAcrossDistinctIdentities(t *testing.T) {
	config = test.ResetTestRoot("blocksync_reactor_test")
	defer os.RemoveAll(config.RootDir)
	genDoc, privVals := genesisDocWithValsPowers([]int64{30})

	pair := newReactor(t, log.TestingLogger(), genDoc, privVals, 5)
	defer func() {
		_ = pair.app.Stop()
	}()

	sharedIP := net.ParseIP("203.0.113.7")
	msg := &bcproto.BlockRequest{Height: 1}

	for i := 0; i < maxIPRequestsPerWindow; i++ {
		peer := p2pmock.NewPeer(sharedIP)
		queued := pair.reactor.Reactor.respondToPeer(msg, peer)
		require.True(t, queued, "request %d (fresh identity, shared IP) within the IP-level limit should be served", i)
		peer.Stop() //nolint:errcheck
	}

	// A brand-new identity on the same IP has never itself sent a request,
	// so the per-identity limiter alone would allow it — but the IP-level
	// budget is already exhausted.
	peer := p2pmock.NewPeer(sharedIP)
	defer peer.Stop() //nolint:errcheck
	queued := pair.reactor.Reactor.respondToPeer(msg, peer)
	require.False(t, queued, "a brand-new identity sharing an already-capped remote IP must still be denied")
}

// TestRespondToPeer_IPLimiterCapsAcrossSharedSubnet exercises the pattern
// a per-exact-address key can't defend against: many distinct exact
// addresses (not one repeated address) inside the same /24, none of which
// individually sends enough requests to matter, but which collectively
// exhaust the subnet's shared budget.
func TestRespondToPeer_IPLimiterCapsAcrossSharedSubnet(t *testing.T) {
	config = test.ResetTestRoot("blocksync_reactor_test")
	defer os.RemoveAll(config.RootDir)
	genDoc, privVals := genesisDocWithValsPowers([]int64{30})

	pair := newReactor(t, log.TestingLogger(), genDoc, privVals, 5)
	defer func() {
		_ = pair.app.Stop()
	}()

	subnet := []string{"203.0.113.5", "203.0.113.9", "203.0.113.250"}
	msg := &bcproto.BlockRequest{Height: 1}

	for i := 0; i < maxIPRequestsPerWindow; i++ {
		peer := p2pmock.NewPeer(net.ParseIP(subnet[i%len(subnet)]))
		queued := pair.reactor.Reactor.respondToPeer(msg, peer)
		require.True(t, queued, "request %d (distinct address, shared /24) within the bucket limit should be served", i)
		peer.Stop() //nolint:errcheck
	}

	peer := p2pmock.NewPeer(net.ParseIP("203.0.113.99"))
	defer peer.Stop() //nolint:errcheck
	queued := pair.reactor.Reactor.respondToPeer(msg, peer)
	require.False(t, queued, "a fourth distinct address in an already-capped /24 must still be denied")
}

// TestAllowBlockRequest_SubnetBanPreventsPeerStateGrowth is the regression
// test for the subnet-ban precheck in allowBlockRequest: once a subnet is
// banned, a brand-new identity in that same subnet must be denied without
// the peer limiter ever recording a window entry for it. Without the
// precheck, an attacker could mint a fresh p2p.ID per connection inside an
// already-banned subnet and force unbounded peer-map growth on our side for
// the rest of the ban's duration, even though every one of those requests
// was always going to be denied by the subnet ban anyway.
func TestAllowBlockRequest_SubnetBanPreventsPeerStateGrowth(t *testing.T) {
	config = test.ResetTestRoot("blocksync_reactor_test")
	defer os.RemoveAll(config.RootDir)
	genDoc, privVals := genesisDocWithValsPowers([]int64{30})

	pair := newReactor(t, log.TestingLogger(), genDoc, privVals, 5)
	defer func() {
		_ = pair.app.Stop()
	}()

	subnet := []string{"203.0.113.5", "203.0.113.9", "203.0.113.250"}
	msg := &bcproto.BlockRequest{Height: 1}

	for i := 0; i < maxIPRequestsPerWindow; i++ {
		peer := p2pmock.NewPeer(net.ParseIP(subnet[i%len(subnet)]))
		queued := pair.reactor.Reactor.respondToPeer(msg, peer)
		require.True(t, queued, "request %d (distinct address, shared /24) within the bucket limit should be served", i)
		peer.Stop() //nolint:errcheck
	}
	banningPeer := p2pmock.NewPeer(net.ParseIP("203.0.113.99"))
	defer banningPeer.Stop() //nolint:errcheck
	queued := pair.reactor.Reactor.respondToPeer(msg, banningPeer)
	require.False(t, queued, "the subnet should now be banned")

	windowsBefore, _ := pair.reactor.reqLimiter.sizes()

	freshPeer := p2pmock.NewPeer(net.ParseIP("203.0.113.200"))
	defer freshPeer.Stop() //nolint:errcheck
	queued = pair.reactor.Reactor.respondToPeer(msg, freshPeer)
	require.False(t, queued, "a fresh identity inside an already-banned subnet must still be denied")

	windowsAfter, _ := pair.reactor.reqLimiter.sizes()
	require.Equal(t, windowsBefore, windowsAfter,
		"the subnet-ban precheck must stop the peer limiter from recording a window entry for a request already doomed by the subnet ban")
}

// TestRespondToPeer_BanSurvivesReconnect proves the rate-limit penalty can't
// be cleared by disconnecting and reconnecting with the same peer identity,
// once a peer has actually been banned for exceeding its window.
func TestRespondToPeer_BanSurvivesReconnect(t *testing.T) {
	config = test.ResetTestRoot("blocksync_reactor_test")
	defer os.RemoveAll(config.RootDir)
	genDoc, privVals := genesisDocWithValsPowers([]int64{30})

	pair := newReactor(t, log.TestingLogger(), genDoc, privVals, 5)
	defer func() {
		_ = pair.app.Stop()
	}()

	peer := p2pmock.NewPeer(nil)
	defer peer.Stop() //nolint:errcheck

	msg := &bcproto.BlockRequest{Height: 1}

	for i := 0; i < maxBlockRequestsPerWindow; i++ {
		queued := pair.reactor.Reactor.respondToPeer(msg, peer)
		require.True(t, queued, "request %d within the per-window limit should be served", i)
	}
	queued := pair.reactor.Reactor.respondToPeer(msg, peer)
	require.False(t, queued, "request beyond the per-window limit should be dropped and trigger a ban")

	// Simulate the peer disconnecting and reconnecting with the same p2p.ID
	// (RemovePeer is exactly what the p2p Switch calls on disconnect).
	pair.reactor.RemovePeer(peer, nil)

	queued = pair.reactor.Reactor.respondToPeer(msg, peer)
	require.False(t, queued, "a banned peer must stay denied after reconnecting with the same identity")
}

// TestRespondToPeer_PersistentPeerBypassesRateLimit is the regression test
// for exemptFromRateLimit: a peer we've explicitly configured as persistent
// must never be throttled by either limiter, however far past both caps its
// requests go. IsPersistent() being unforgeable (see exemptFromRateLimit's
// doc comment) is what makes this safe.
func TestRespondToPeer_PersistentPeerBypassesRateLimit(t *testing.T) {
	config = test.ResetTestRoot("blocksync_reactor_test")
	defer os.RemoveAll(config.RootDir)
	genDoc, privVals := genesisDocWithValsPowers([]int64{30})

	pair := newReactor(t, log.TestingLogger(), genDoc, privVals, 5)
	defer func() {
		_ = pair.app.Stop()
	}()

	peer := p2pmock.NewPeer(nil)
	peer.Persistent = true
	defer peer.Stop() //nolint:errcheck

	msg := &bcproto.BlockRequest{Height: 1}

	for i := 0; i < maxBlockRequestsPerWindow+maxIPRequestsPerWindow; i++ {
		queued := pair.reactor.Reactor.respondToPeer(msg, peer)
		require.True(t, queued, "request %d from a persistent peer must never be throttled", i)
	}
}

// TestRespondToPeer_NonPersistentPeerStillRateLimited proves the exemption
// added for persistent peers didn't accidentally loosen the limiter for
// everyone else — a non-persistent peer is capped exactly as before.
func TestRespondToPeer_NonPersistentPeerStillRateLimited(t *testing.T) {
	config = test.ResetTestRoot("blocksync_reactor_test")
	defer os.RemoveAll(config.RootDir)
	genDoc, privVals := genesisDocWithValsPowers([]int64{30})

	pair := newReactor(t, log.TestingLogger(), genDoc, privVals, 5)
	defer func() {
		_ = pair.app.Stop()
	}()

	peer := p2pmock.NewPeer(nil)
	require.False(t, peer.IsPersistent())
	defer peer.Stop() //nolint:errcheck

	msg := &bcproto.BlockRequest{Height: 1}

	for i := 0; i < maxBlockRequestsPerWindow; i++ {
		queued := pair.reactor.Reactor.respondToPeer(msg, peer)
		require.True(t, queued, "request %d within the per-window limit should be served", i)
	}

	queued := pair.reactor.Reactor.respondToPeer(msg, peer)
	require.False(t, queued, "a non-persistent peer beyond the per-window limit must still be dropped")
}

// NOTE: This is too hard to test without
// an easy way to add test peer to switch
// or without significant refactoring of the module.
// Alternatively we could actually dial a TCP conn but
// that seems extreme.
func TestBadBlockStopsPeer(t *testing.T) {
	config = test.ResetTestRoot("blocksync_reactor_test")
	defer os.RemoveAll(config.RootDir)
	genDoc, privVals := genesisDocWithValsPowers([]int64{30})

	maxBlockHeight := int64(148)

	// Other chain needs a different validator set
	otherGenDoc, otherPrivVals := genesisDocWithValsPowers([]int64{30})
	otherChain := newReactor(t, log.TestingLogger(), otherGenDoc, otherPrivVals, maxBlockHeight)

	defer func() {
		err := otherChain.reactor.Stop()
		require.Error(t, err)
		err = otherChain.app.Stop()
		require.NoError(t, err)
	}()

	reactorPairs := make([]ReactorPair, 4) //nolint:prealloc

	reactorPairs[0] = newReactor(t, log.TestingLogger(), genDoc, privVals, maxBlockHeight)
	reactorPairs[1] = newReactor(t, log.TestingLogger(), genDoc, privVals, 0)
	reactorPairs[2] = newReactor(t, log.TestingLogger(), genDoc, privVals, 0)
	reactorPairs[3] = newReactor(t, log.TestingLogger(), genDoc, privVals, 0)

	switches := p2p.MakeConnectedSwitches(config.P2P, 4, func(i int, s *p2p.Switch) *p2p.Switch {
		s.AddReactor("BLOCKSYNC", reactorPairs[i].reactor)
		return s
	}, p2p.Connect2Switches)

	defer func() {
		for _, r := range reactorPairs {
			err := r.reactor.Stop()
			require.NoError(t, err)

			err = r.app.Stop()
			require.NoError(t, err)
		}
	}()

	for {
		time.Sleep(1 * time.Second)
		caughtUp := true
		for _, r := range reactorPairs {
			if !r.reactor.pool.IsCaughtUp() {
				caughtUp = false
			}
		}
		if caughtUp {
			break
		}
	}

	// at this time, reactors[0-3] is the newest
	assert.Equal(t, 3, reactorPairs[1].reactor.Switch.Peers().Size())

	// Mark reactorPairs[3] as an invalid peer. Fiddling with .store without a mutex is a data
	// race, but can't be easily avoided.
	reactorPairs[3].reactor.store = otherChain.reactor.store

	lastReactorPair := newReactor(t, log.TestingLogger(), genDoc, privVals, 0)
	reactorPairs = append(reactorPairs, lastReactorPair)

	switches = append(switches, p2p.MakeConnectedSwitches(config.P2P, 1, func(i int, s *p2p.Switch) *p2p.Switch {
		s.AddReactor("BLOCKSYNC", reactorPairs[len(reactorPairs)-1].reactor)
		return s
	}, p2p.Connect2Switches)...)

	for i := 0; i < len(reactorPairs)-1; i++ {
		p2p.Connect2Switches(switches, i, len(reactorPairs)-1)
	}

	for !lastReactorPair.reactor.pool.IsCaughtUp() && lastReactorPair.reactor.Switch.Peers().Size() != 0 {

		time.Sleep(1 * time.Second)
	}

	assert.True(t, lastReactorPair.reactor.Switch.Peers().Size() < len(reactorPairs)-1)
}

func TestCheckSwitchToConsensusLastHeightZero(t *testing.T) {
	const maxBlockHeight = int64(45)

	config = test.ResetTestRoot("blocksync_reactor_test")
	defer os.RemoveAll(config.RootDir)
	genDoc, privVals := genesisDocWithValsPowers([]int64{30})

	reactorPairs := make([]ReactorPair, 1, 2)
	reactorPairs[0] = newReactor(t, log.TestingLogger(), genDoc, privVals, 0)
	reactorPairs[0].reactor.switchToConsensusMs = 50
	defer func() {
		for _, r := range reactorPairs {
			err := r.reactor.Stop()
			require.NoError(t, err)
			err = r.app.Stop()
			require.NoError(t, err)
		}
	}()

	reactorPairs = append(reactorPairs, newReactor(t, log.TestingLogger(), genDoc, privVals, maxBlockHeight))

	var switches []*p2p.Switch //nolint:prealloc
	for _, r := range reactorPairs {
		switches = append(switches, p2p.MakeConnectedSwitches(config.P2P, 1, func(i int, s *p2p.Switch) *p2p.Switch {
			s.AddReactor("BLOCKSYNC", r.reactor)
			return s
		}, p2p.Connect2Switches)...)
	}

	time.Sleep(60 * time.Millisecond)

	// Connect both switches
	p2p.Connect2Switches(switches, 0, 1)

	startTime := time.Now()
	for {
		time.Sleep(20 * time.Millisecond)
		caughtUp := true
		for _, r := range reactorPairs {
			if !r.reactor.pool.IsCaughtUp() {
				caughtUp = false
				break
			}
		}
		if caughtUp {
			break
		}
		if time.Since(startTime) > 90*time.Second {
			msg := "timeout: reactors didn't catch up;"
			for i, r := range reactorPairs {
				h, p, lr := r.reactor.pool.GetStatus()
				c := r.reactor.pool.IsCaughtUp()
				msg += fmt.Sprintf(" reactor#%d (h %d, p %d, lr %d, c %t);", i, h, p, lr, c)
			}
			require.Fail(t, msg)
		}
	}

	// -1 because of "-1" in IsCaughtUp
	// -1 pool.height points to the _next_ height
	// -1 because we measure height of block store
	const maxDiff = 3
	for _, r := range reactorPairs {
		assert.GreaterOrEqual(t, r.reactor.store.Height(), maxBlockHeight-maxDiff)
	}
}

func ExtendedCommitNetworkHelper(t *testing.T, maxBlockHeight int64, enableVoteExtensionAt int64, valPowers []int64, opts ...reactorOption) {
	config = test.ResetTestRoot("blocksync_reactor_test")
	defer os.RemoveAll(config.RootDir)
	genDoc, privVals := genesisDocWithValsPowers(valPowers)
	genDoc.ConsensusParams.ABCI.VoteExtensionsEnableHeight = enableVoteExtensionAt

	reactorPairs := make([]ReactorPair, 1, 2)
	reactorPairs[0] = newReactor(t, log.TestingLogger(), genDoc, privVals, 0)
	reactorPairs[0].reactor.switchToConsensusMs = 50
	defer func() {
		for _, r := range reactorPairs {
			_ = r.reactor.Stop()
			_ = r.app.Stop()
		}
	}()

	reactorPairs = append(reactorPairs, newReactor(t, log.TestingLogger(), genDoc, privVals, maxBlockHeight, opts...))

	var switches []*p2p.Switch //nolint:prealloc
	for _, r := range reactorPairs {
		switches = append(switches, p2p.MakeConnectedSwitches(config.P2P, 1, func(i int, s *p2p.Switch) *p2p.Switch {
			s.AddReactor("BLOCKSYNC", r.reactor)
			return s
		}, p2p.Connect2Switches)...)
	}

	time.Sleep(60 * time.Millisecond)

	// Connect both switches
	p2p.Connect2Switches(switches, 0, 1)

	startTime := time.Now()
	for {
		time.Sleep(20 * time.Millisecond)
		// The reactor can never catch up, because at one point it disconnects.
		require.False(t, reactorPairs[0].reactor.pool.IsCaughtUp(), "node caught up when it should not have")
		// After 5 seconds, the test should have executed.
		if time.Since(startTime) > 5*time.Second {
			assert.Equal(t, 0, reactorPairs[0].reactor.Switch.Peers().Size(), "node should have disconnected but didn't")
			assert.Equal(t, 0, reactorPairs[1].reactor.Switch.Peers().Size(), "node should have disconnected but didn't")
			break
		}
	}
}

func TestCheckExtendedCommit(t *testing.T) {
	tests := []struct {
		name                  string
		maxBlockHeight        int64
		enableVoteExtensionAt int64
		valPowers             []int64
		opts                  []reactorOption
	}{
		{
			name:                  "extra ext commit when disabled",
			maxBlockHeight:        10,
			enableVoteExtensionAt: 5,
			valPowers:             []int64{30, 1},
			opts:                  []reactorOption{withCorruptedBlock(3)},
		},
		{
			name:                  "missing ext commit when enabled",
			maxBlockHeight:        10,
			enableVoteExtensionAt: 5,
			valPowers:             []int64{30, 1},
			opts:                  []reactorOption{withCorruptedBlock(8)},
		},
		{
			name:                  "all absent signatures",
			maxBlockHeight:        10,
			enableVoteExtensionAt: 1,
			valPowers:             []int64{30, 1},
			opts:                  []reactorOption{withAllAbsentExtCommitBlock(5)},
		},
		{
			name:                  "invalid signature after 2/3+ threshold",
			maxBlockHeight:        10,
			enableVoteExtensionAt: 1,
			valPowers:             []int64{10, 10, 10, 1},
			opts:                  []reactorOption{withInvalidExtCommitBlock(5)},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ExtendedCommitNetworkHelper(t, tc.maxBlockHeight, tc.enableVoteExtensionAt, tc.valPowers, tc.opts...)
		})
	}
}

// ByzantineReactor is a blockstore reactor implementation where a corrupted block can be sent to a peer.
// The corruption is that the block contains extended commit signatures when vote extensions are disabled or
// it has no extended commit signatures while vote extensions are enabled.
// If the corrupted block height is set to 0, the reactor behaves as normal.
type ByzantineReactor struct {
	*Reactor
	corruptedBlock        int64
	absentExtCommitBlock  int64
	invalidExtCommitBlock int64
}

func NewByzantineReactor(conR *Reactor) *ByzantineReactor {
	return &ByzantineReactor{
		Reactor: conR,
	}
}

// respondToPeer (overridden method) loads a block and sends it to the requesting peer,
// if we have it. Otherwise, we'll respond saying we don't have it.
// Byzantine modification: if corruptedBlock is set, send the wrong Block.
func (bcR *ByzantineReactor) respondToPeer(msg *bcproto.BlockRequest, src p2p.Peer) (queued bool) {
	block := bcR.store.LoadBlock(msg.Height)
	if block == nil {
		bcR.Logger.Info("Peer asking for a block we don't have", "src", src, "height", msg.Height)
		return src.TrySend(p2p.Envelope{
			ChannelID: BlocksyncChannel,
			Message:   &bcproto.NoBlockResponse{Height: msg.Height},
		})
	}

	state, err := bcR.blockExec.Store().Load()
	if err != nil {
		bcR.Logger.Error("loading state", "err", err)
		return false
	}
	var extCommit *types.ExtendedCommit
	voteExtensionEnabled := state.ConsensusParams.ABCI.VoteExtensionsEnabled(msg.Height)
	incorrectBlock := bcR.corruptedBlock == msg.Height
	if voteExtensionEnabled && !incorrectBlock || !voteExtensionEnabled && incorrectBlock {
		extCommit = bcR.store.LoadBlockExtendedCommit(msg.Height)
		if extCommit == nil {
			bcR.Logger.Error("found block in store with no extended commit", "block", block)
			return false
		}
	}

	if bcR.absentExtCommitBlock == msg.Height && extCommit != nil {
		absentSigs := make([]types.ExtendedCommitSig, len(extCommit.ExtendedSignatures))
		for i := range absentSigs {
			absentSigs[i] = types.NewExtendedCommitSigAbsent()
		}
		extCommit = &types.ExtendedCommit{
			Height:             extCommit.Height,
			Round:              extCommit.Round,
			BlockID:            extCommit.BlockID,
			ExtendedSignatures: absentSigs,
		}
	}

	if bcR.invalidExtCommitBlock == msg.Height && extCommit != nil {
		extCommit.ExtendedSignatures[len(extCommit.ExtendedSignatures)-1].Signature = []byte("invalid signature")
	}

	bl, err := block.ToProto()
	if err != nil {
		bcR.Logger.Error("could not convert msg to protobuf", "err", err)
		return false
	}

	return src.TrySend(p2p.Envelope{
		ChannelID: BlocksyncChannel,
		Message: &bcproto.BlockResponse{
			Block:     bl,
			ExtCommit: extCommit.ToProto(),
		},
	})
}

// Receive implements Reactor by handling 4 types of messages (look below).
// Copied unchanged from reactor.go so the correct respondToPeer is called.
func (bcR *ByzantineReactor) Receive(e p2p.Envelope) {
	if err := ValidateMsg(e.Message); err != nil {
		bcR.Logger.Error("Peer sent us invalid msg", "peer", e.Src, "msg", e.Message, "err", err)
		bcR.Switch.StopPeerForError(e.Src, err)
		return
	}

	bcR.Logger.Debug("Receive", "e.Src", e.Src, "chID", e.ChannelID, "msg", e.Message)

	switch msg := e.Message.(type) {
	case *bcproto.BlockRequest:
		bcR.respondToPeer(msg, e.Src)
	case *bcproto.BlockResponse:
		bi, err := types.BlockFromProto(msg.Block)
		if err != nil {
			bcR.Logger.Error("Peer sent us invalid block", "peer", e.Src, "msg", e.Message, "err", err)
			bcR.Switch.StopPeerForError(e.Src, err)
			return
		}
		var extCommit *types.ExtendedCommit
		if msg.ExtCommit != nil {
			var err error
			extCommit, err = types.ExtendedCommitFromProto(msg.ExtCommit)
			if err != nil {
				bcR.Logger.Error("failed to convert extended commit from proto",
					"peer", e.Src,
					"err", err)
				bcR.Switch.StopPeerForError(e.Src, err)
				return
			}
		}

		if err := bcR.pool.AddBlock(e.Src.ID(), bi, extCommit, msg.Block.Size()); err != nil {
			bcR.Logger.Error("failed to add block", "peer", e.Src, "err", err)
		}
	case *bcproto.StatusRequest:
		// Send peer our state.
		e.Src.TrySend(p2p.Envelope{
			ChannelID: BlocksyncChannel,
			Message: &bcproto.StatusResponse{
				Height: bcR.store.Height(),
				Base:   bcR.store.Base(),
			},
		})
	case *bcproto.StatusResponse:
		// Got a peer status. Unverified.
		bcR.pool.SetPeerRange(e.Src.ID(), msg.Base, msg.Height)
	case *bcproto.NoBlockResponse:
		bcR.Logger.Debug("Peer does not have requested block", "peer", e.Src, "height", msg.Height)
		bcR.pool.RedoRequestFrom(msg.Height, e.Src.ID())
	default:
		bcR.Logger.Error(fmt.Sprintf("Unknown message type %v", reflect.TypeOf(msg)))
	}
}
