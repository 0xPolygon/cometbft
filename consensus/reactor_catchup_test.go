package consensus

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfg "github.com/cometbft/cometbft/config"
	cstypes "github.com/cometbft/cometbft/consensus/types"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/p2p"
	p2pmock "github.com/cometbft/cometbft/p2p/mock"
	"github.com/cometbft/cometbft/types"
)

func TestEvaluateBehind(t *testing.T) {
	tests := []struct {
		name            string
		lagThreshold    int64
		myHeight        int64
		peerHeights     []int64
		isSoleValidator bool
		want            bool
	}{
		{"majority far ahead", 5, 100, []int64{110, 110, 110}, false, true},
		{"single peer ahead is minority", 5, 100, []int64{110, 100, 100}, false, false},
		{"majority of three ahead", 5, 100, []int64{110, 110, 100}, false, true},
		{"two peers split is not majority", 5, 100, []int64{110, 100}, false, false},
		{"both peers ahead", 5, 100, []int64{110, 110}, false, true},
		{"lone peer cannot corroborate", 5, 100, []int64{110}, false, false},
		{"lone peer far ahead still cannot corroborate", 5, 100, []int64{100000}, false, false},
		{"peers within threshold", 5, 100, []int64{105, 105, 105}, false, false},
		{"majority one over threshold", 5, 100, []int64{106, 106, 106}, false, true},
		{"equal height network halt", 5, 100, []int64{100, 100, 100}, false, false},
		{"round skew one ahead", 5, 100, []int64{101, 101, 101}, false, false},
		{"no peer height learned", 5, 100, []int64{0, 0, 0}, false, false},
		{"threshold disabled ignores lag", 0, 100, []int64{999, 999, 999}, false, false},
		{"sole validator zero peers healthy", 5, 100, nil, true, false},
		{"non-sole zero peers behind", 5, 100, nil, false, true},
		{"zero peers behind even when lag disabled", 0, 100, nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conR := &Reactor{
				catchUpLagThreshold: tt.lagThreshold,
			}
			got := conR.evaluateBehind(tt.myHeight, tt.peerHeights, tt.isSoleValidator)
			assert.Equal(t, tt.want, got)
		})
	}
}

// peerWithHeight returns a mock peer carrying a consensus PeerState at height h.
func peerWithHeight(h int64) *p2pmock.Peer {
	p := p2pmock.NewPeer(nil)
	ps := NewPeerState(p)
	ps.PRS.Height = h
	p.Set(types.PeerStateKey, ps)
	return p
}

func TestCollectPeerHeights(t *testing.T) {
	t.Run("no peers yields empty slice", func(t *testing.T) {
		assert.Empty(t, collectPeerHeights(nil))
	})

	t.Run("collects every peer height in order", func(t *testing.T) {
		peers := []p2p.Peer{peerWithHeight(100), peerWithHeight(110), peerWithHeight(90)}
		assert.Equal(t, []int64{100, 110, 90}, collectPeerHeights(peers))
	})

	t.Run("skips peer without a PeerState", func(t *testing.T) {
		peers := []p2p.Peer{peerWithHeight(100), p2pmock.NewPeer(nil), peerWithHeight(110)}
		assert.Equal(t, []int64{100, 110}, collectPeerHeights(peers))
	})

	t.Run("skips peer with a non-PeerState value at the key", func(t *testing.T) {
		bad := p2pmock.NewPeer(nil)
		bad.Set(types.PeerStateKey, "not a peer state")
		peers := []p2p.Peer{peerWithHeight(100), bad}
		assert.Equal(t, []int64{100}, collectPeerHeights(peers))
	})
}

func TestIsLocalSoleValidator(t *testing.T) {
	val, _ := types.RandValidator(false, 10)
	other, _ := types.RandValidator(false, 10)

	tests := []struct {
		name   string
		pubKey crypto.PubKey
		valSet *types.ValidatorSet
		want   bool
	}{
		{"sole validator and we are it", val.PubKey, types.NewValidatorSet([]*types.Validator{val}), true},
		{"sole validator but it is not us", other.PubKey, types.NewValidatorSet([]*types.Validator{val}), false},
		{"we are in a larger set", val.PubKey, types.NewValidatorSet([]*types.Validator{val, other}), false},
		{"no local validator key", nil, types.NewValidatorSet([]*types.Validator{val}), false},
		{"no validator set", val.PubKey, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := &State{}
			cs.privValidatorPubKey = tt.pubKey
			cs.Validators = tt.valSet
			assert.Equal(t, tt.want, cs.isLocalSoleValidator())
		})
	}
}

func TestReactorCatchupConfig(t *testing.T) {
	conR := &Reactor{}
	ReactorCatchupConfig(7, 3*time.Second)(conR)
	assert.Equal(t, int64(7), conR.catchUpLagThreshold)
	assert.Equal(t, 3*time.Second, conR.catchUpDebounce)
}

// newCatchupReactor wires a Reactor with a non-started Switch carrying mock peers
// at the given heights, a round state at myHeight, and (optionally) a single-validator
// set that this node belongs to. catchUpDebounce is 0 so IsBehind reflects the raw
// decision immediately, keeping the test free of timing.
func newCatchupReactor(t *testing.T, myHeight int64, sole bool, peerHeights ...int64) *Reactor {
	t.Helper()
	cs := &State{}
	if sole {
		val, _ := types.RandValidator(false, 10)
		cs.Validators = types.NewValidatorSet([]*types.Validator{val})
		cs.privValidatorPubKey = val.PubKey
	}
	conR := &Reactor{
		conS:                cs,
		rs:                  &cstypes.RoundState{Height: myHeight},
		catchUpLagThreshold: 5,
		catchUpDebounce:     0,
	}
	conR.BaseReactor = *p2p.NewBaseReactor("Consensus", conR)

	sw := p2p.NewSwitch(cfg.DefaultP2PConfig(), nil)
	peerSet := sw.Peers().(*p2p.PeerSet)
	for _, h := range peerHeights {
		require.NoError(t, peerSet.Add(peerWithHeight(h)))
	}
	conR.SetSwitch(sw)
	return conR
}

// TestIsBehindIntegration exercises the full IsBehind path (Switch peers ->
// collectPeerHeights -> evaluateBehind, plus the sole-validator and debounce
// wiring) rather than the pure decision helpers in isolation.
func TestIsBehindIntegration(t *testing.T) {
	t.Run("majority of peers ahead reports behind", func(t *testing.T) {
		assert.True(t, newCatchupReactor(t, 100, false, 110, 110, 110).IsBehind())
	})
	t.Run("synced multi-peer network is not behind", func(t *testing.T) {
		assert.False(t, newCatchupReactor(t, 100, false, 100, 100, 100).IsBehind())
	})
	t.Run("lone peer ahead cannot corroborate", func(t *testing.T) {
		assert.False(t, newCatchupReactor(t, 100, false, 110).IsBehind())
	})
	t.Run("no peers and not sole validator is behind", func(t *testing.T) {
		assert.True(t, newCatchupReactor(t, 100, false).IsBehind())
	})
	t.Run("no peers but sole validator is not behind", func(t *testing.T) {
		assert.False(t, newCatchupReactor(t, 100, true).IsBehind())
	})
}

func TestApplyDebounce(t *testing.T) {
	debounce := 10 * time.Second
	t0 := time.Now()

	t.Run("not behind resets and returns false", func(t *testing.T) {
		conR := &Reactor{catchUpDebounce: debounce, behindSince: t0}
		assert.False(t, conR.applyDebounceLocked(false, t0.Add(time.Hour)))
		assert.True(t, conR.behindSince.IsZero())
	})

	t.Run("behind but within debounce stays false", func(t *testing.T) {
		conR := &Reactor{catchUpDebounce: debounce}
		assert.False(t, conR.applyDebounceLocked(true, t0))
		assert.False(t, conR.applyDebounceLocked(true, t0.Add(5*time.Second)))
	})

	t.Run("behind past debounce flips true", func(t *testing.T) {
		conR := &Reactor{catchUpDebounce: debounce}
		assert.False(t, conR.applyDebounceLocked(true, t0))
		assert.True(t, conR.applyDebounceLocked(true, t0.Add(debounce)))
	})

	t.Run("transient blip resets the timer", func(t *testing.T) {
		conR := &Reactor{catchUpDebounce: debounce}
		assert.False(t, conR.applyDebounceLocked(true, t0))
		assert.False(t, conR.applyDebounceLocked(false, t0.Add(5*time.Second)))
		// timer restarts; not yet past debounce from the new start.
		assert.False(t, conR.applyDebounceLocked(true, t0.Add(6*time.Second)))
		assert.True(t, conR.applyDebounceLocked(true, t0.Add(16*time.Second)))
	})

	t.Run("zero debounce flips immediately", func(t *testing.T) {
		conR := &Reactor{catchUpDebounce: 0}
		assert.True(t, conR.applyDebounceLocked(true, t0))
	})
}
