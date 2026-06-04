package consensus

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEvaluateBehind(t *testing.T) {
	tests := []struct {
		name            string
		lagThreshold    int64
		myHeight        int64
		maxPeerHeight   int64
		nPeers          int
		isSoleValidator bool
		want            bool
	}{
		{"peer far ahead", 5, 100, 110, 3, false, true},
		{"peer ahead within threshold", 5, 100, 105, 3, false, false},
		{"peer one over threshold", 5, 100, 106, 3, false, true},
		{"equal height network halt", 5, 100, 100, 3, false, false},
		{"round skew peer one ahead", 5, 100, 101, 3, false, false},
		{"no peer height learned", 5, 100, 0, 3, false, false},
		{"threshold disabled ignores lag", 0, 100, 999, 3, false, false},
		{"sole validator zero peers healthy", 5, 100, 0, 0, true, false},
		{"non-sole zero peers behind", 5, 100, 0, 0, false, true},
		{"zero peers behind even when lag disabled", 0, 100, 0, 0, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conR := &Reactor{
				catchUpLagThreshold: tt.lagThreshold,
			}
			got := conR.evaluateBehind(tt.myHeight, tt.maxPeerHeight, tt.nPeers, tt.isSoleValidator)
			assert.Equal(t, tt.want, got)
		})
	}
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
