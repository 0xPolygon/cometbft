package blocksync

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/p2p"
)

func TestByteBudgetReserveAndRefill(t *testing.T) {
	start := time.Now()
	b := newByteBudget(100, 200)
	b.last = start
	b.tokens = 200

	require.True(t, b.reserveAt(150, start), "within burst")
	require.False(t, b.reserveAt(100, start), "only 50 left")
	require.True(t, b.reserveAt(50, start), "exactly the remainder")

	// A second of refill is worth exactly rate, and never more than burst.
	require.True(t, b.reserveAt(100, start.Add(time.Second)))
	require.False(t, b.reserveAt(1, start.Add(time.Second)))
	require.True(t, b.reserveAt(200, start.Add(time.Hour)), "capped at burst, not hours of rate")
	require.False(t, b.reserveAt(1, start.Add(time.Hour)))
}

func TestByteBudgetSettleCarriesDebt(t *testing.T) {
	start := time.Now()
	b := newByteBudget(100, 200)
	b.last = start
	b.tokens = 200

	require.True(t, b.reserveAt(200, start))
	// An under-estimated response has to be paid, not forgiven, so the
	// bucket is allowed to go negative and refill the debt off.
	b.settleAt(300, start)
	assert.Equal(t, -300.0, b.tokens)
	require.False(t, b.reserveAt(1, start), "in debt, nothing available")

	// Four seconds of rate clears the debt and leaves 100.
	require.True(t, b.reserveAt(100, start.Add(4*time.Second)))
}

func TestByteBudgetReleaseCannotExceedBurst(t *testing.T) {
	start := time.Now()
	b := newByteBudget(100, 200)
	b.last = start
	b.tokens = 200

	b.release(500)
	assert.LessOrEqual(t, b.available(), 200.0, "a release must not manufacture capacity")
}

func TestKeyedBudgetsDisabledWhenRateZero(t *testing.T) {
	k := newKeyedBudgets(0, 0)
	for i := 0; i < 100; i++ {
		require.True(t, k.reserve("any", 1<<30), "a zero rate disables the layer entirely")
	}
	assert.Zero(t, k.size(), "a disabled layer tracks nothing")
}

func TestKeyedBudgetsIsolatesKeys(t *testing.T) {
	k := newKeyedBudgets(100, 100)

	require.True(t, k.reserve("a", 100))
	require.False(t, k.reserve("a", 1), "key a is spent")
	require.True(t, k.reserve("b", 100), "key b has its own allowance")
	assert.Equal(t, 2, k.size())
}

func TestKeyedBudgetsSweepNeverGrantsFreshAllowance(t *testing.T) {
	now := time.Now()
	k := newKeyedBudgets(100, 100)
	require.True(t, k.reserve("spent", 100))

	// Retiring a spent bucket would hand its key a brand new allowance,
	// which is exactly the bypass a rotating requester would want.
	k.sweep(now)
	assert.Equal(t, 1, k.size(), "a bucket still in debt must not be retired")
	require.False(t, k.reserve("spent", 1))

	// Once it has refilled it holds no state worth keeping.
	k.sweep(now.Add(2 * time.Second))
	assert.Zero(t, k.size(), "a refilled bucket is retired")
}

// servingTestConfig is small enough to reason about in bytes: 1000 B/s
// node-wide, 400 B/s per subnet, and a 600 B quota per address per hour.
func servingTestConfig() ServingConfig {
	return ServingConfig{
		Rate:        1000,
		Burst:       1000,
		SubnetRate:  400,
		Quota:       600,
		QuotaPeriod: time.Hour,
	}
}

func TestServingBudgetGlobalCeilingHoldsAcrossRotatingIdentities(t *testing.T) {
	s := newServingBudget(ServingConfig{Rate: 1000, Burst: 1000})

	// Every request is a fresh identity, address and subnet — the shape a
	// requester takes when minting a node key per connection. The node-wide
	// ceiling is the layer that has to hold anyway.
	var served float64
	for i := 0; i < 50; i++ {
		id := p2p.ID(fmt.Sprintf("peer-%d", i))
		addr := fmt.Sprintf("10.0.%d.1", i)
		subnet := fmt.Sprintf("10.0.%d.0", i)
		if s.reserve(id, addr, subnet, 100) {
			served += 100
		}
	}
	assert.Equal(t, 1000.0, served, "rotating identities must not raise aggregate throughput")
}

func TestServingBudgetSubnetShareBoundsOnePrefix(t *testing.T) {
	s := newServingBudget(servingTestConfig())

	// Rotating addresses inside one prefix should not buy more than the
	// prefix's share, even though each address has its own quota.
	var served float64
	for i := 0; i < 20; i++ {
		addr := fmt.Sprintf("10.0.0.%d", i)
		if s.reserve(p2p.ID(fmt.Sprintf("p%d", i)), addr, "10.0.0.0", 100) {
			served += 100
		}
	}
	assert.Equal(t, 800.0, served, "bounded by the subnet burst (2x rate), not by the node-wide ceiling")
}

func TestServingBudgetQuotaBoundsOneAddress(t *testing.T) {
	s := newServingBudget(servingTestConfig())

	// One address, one identity: the quota is what stops it, before either
	// rate layer would.
	var served float64
	for i := 0; i < 20; i++ {
		if s.reserve("peer", "10.0.0.1", "10.0.0.0", 100) {
			served += 100
		}
	}
	assert.Equal(t, 600.0, served, "capped at the per-address quota")

	// A different address in the same prefix still has its own quota, up to
	// the prefix's share.
	require.True(t, s.reserve("other", "10.0.0.2", "10.0.0.0", 100))
}

func TestServingBudgetExemptBypassesKeyedLayersButNotGlobal(t *testing.T) {
	cfg := servingTestConfig()
	cfg.ExemptIDs = []p2p.ID{"partner"}
	s := newServingBudget(cfg)

	// Well past both the per-address quota (600) and the subnet share (800).
	var served float64
	for i := 0; i < 20; i++ {
		if s.reserve("partner", "10.0.0.1", "10.0.0.0", 100) {
			served += 100
		}
	}
	assert.Equal(t, 1000.0, served,
		"an exemption lifts the quota and subnet share but not the node-wide ceiling")
}

func TestServingBudgetRefundsKeyedLayersWhenGlobalRefuses(t *testing.T) {
	s := newServingBudget(ServingConfig{
		Rate: 100, Burst: 100, SubnetRate: 1000, Quota: 1000, QuotaPeriod: time.Hour,
	})

	require.True(t, s.reserve("peer", "10.0.0.1", "10.0.0.0", 100), "drains the global bucket")
	require.False(t, s.reserve("peer", "10.0.0.1", "10.0.0.0", 100), "global is spent")

	// The refused request must not have charged the subnet share or the
	// address quota on its way out, or a requester spread thin across many
	// prefixes would burn everyone's allowance against a ceiling that never
	// served it anything. Only the first, served request should be charged:
	// the subnet bucket bursts to 2x its rate, so 2000 - 100, and the quota
	// bucket to the quota itself, so 1000 - 100.
	assert.InDelta(t, 1900.0, s.subnets.get("10.0.0.0").available(), 1.0)
	assert.InDelta(t, 900.0, s.quotas.get("10.0.0.1").available(), 1.0)
}

func TestServingReservationLifecycle(t *testing.T) {
	newRes := func(s *servingBudget) *servingReservation {
		require.True(t, s.reserve("peer", "10.0.0.1", "10.0.0.0", 100))
		return &servingReservation{
			budget: s, id: "peer", addr: "10.0.0.1", subnet: "10.0.0.0", held: 100,
		}
	}

	t.Run("release returns the unspent charge", func(t *testing.T) {
		s := newServingBudget(ServingConfig{Rate: 1000, Burst: 1000})
		r := newRes(s)
		r.release()
		assert.InDelta(t, 1000.0, s.globalAvailable(), 1.0)
	})

	t.Run("release is idempotent", func(t *testing.T) {
		s := newServingBudget(ServingConfig{Rate: 1000, Burst: 1000})
		r := newRes(s)
		r.release()
		r.release()
		assert.InDelta(t, 1000.0, s.globalAvailable(), 1.0, "a double release must not refund twice")
	})

	t.Run("commit keeps the charge and disarms release", func(t *testing.T) {
		s := newServingBudget(ServingConfig{Rate: 1000, Burst: 1000})
		r := newRes(s)
		r.commit()
		r.release()
		assert.InDelta(t, 900.0, s.globalAvailable(), 1.0, "committed bytes stay spent")
	})

	t.Run("settle reconciles an under-estimate and release gives back the real size", func(t *testing.T) {
		s := newServingBudget(ServingConfig{Rate: 1000, Burst: 1000})
		r := newRes(s)
		require.True(t, r.settle(250))
		assert.InDelta(t, 750.0, s.globalAvailable(), 1.0, "charged the real size, not the estimate")
		r.release()
		assert.InDelta(t, 1000.0, s.globalAvailable(), 1.0, "releases what it actually held")
	})

	t.Run("an exempt reservation holds nothing", func(t *testing.T) {
		r := &servingReservation{}
		require.True(t, r.settle(1<<30), "an exempt reservation always settles")
		r.commit()
		r.release()
		assert.Zero(t, r.held)
	})
}

func TestQuotaRate(t *testing.T) {
	testCases := []struct {
		name string
		cfg  ServingConfig
		want float64
	}{
		{"disabled without a quota", ServingConfig{QuotaPeriod: time.Hour}, 0},
		{"disabled without a period", ServingConfig{Quota: 100}, 0},
		{"quota spread over the period", ServingConfig{Quota: 3600, QuotaPeriod: time.Hour}, 1},
		{"sub-second period", ServingConfig{Quota: 100, QuotaPeriod: 500 * time.Millisecond}, 200},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, quotaRate(tc.cfg))
		})
	}
}

func TestParseExemptPeerIDs(t *testing.T) {
	testCases := []struct {
		name string
		in   string
		want []p2p.ID
	}{
		{"empty", "", nil},
		{"only separators", " , ,", nil},
		{"single", "abc", []p2p.ID{"abc"}},
		{"trims and skips blanks", " abc , ,def ", []p2p.ID{"abc", "def"}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParseExemptPeerIDs(tc.in))
		})
	}
}

func TestNewServingBudgetDefaultsAndDisabling(t *testing.T) {
	t.Run("zero burst defaults to two seconds of rate", func(t *testing.T) {
		s := newServingBudget(ServingConfig{Rate: 500})
		assert.Equal(t, 1000.0, s.global.burst)
	})

	t.Run("zero rate disables the node-wide ceiling", func(t *testing.T) {
		s := newServingBudget(ServingConfig{})
		require.Nil(t, s.global)
		require.True(t, s.reserve("peer", "10.0.0.1", "10.0.0.0", 1<<30))
		assert.True(t, math.IsInf(s.globalAvailable(), 1), "reports unbounded rather than panicking")
	})
}

// recordingGauge captures the last value set, so the sweep's reporting can be
// asserted rather than merely executed.
type recordingGauge struct{ value float64 }

func (g *recordingGauge) With(...string) metrics.Gauge { return g }
func (g *recordingGauge) Set(v float64)                { g.value = v }
func (g *recordingGauge) Add(d float64)                { g.value += d }

func TestSweepServingBudgetReportsPostSweepState(t *testing.T) {
	s := newServingBudget(servingTestConfig())
	require.True(t, s.reserve("peer", "10.0.0.1", "10.0.0.0", 100))

	tokens, subnets, quotas := &recordingGauge{}, &recordingGauge{}, &recordingGauge{}
	sweepServingBudget(s, time.Now(), tokens, subnets, quotas)

	assert.InDelta(t, 900.0, tokens.value, 1.0, "node-wide tokens remaining after the charge")
	assert.Equal(t, 1.0, subnets.value, "one tracked prefix")
	assert.Equal(t, 1.0, quotas.value, "one tracked address")

	// Far enough ahead that both keyed buckets have refilled and are retired.
	sweepServingBudget(s, time.Now().Add(2*time.Hour), tokens, subnets, quotas)
	assert.Zero(t, subnets.value, "idle prefix buckets are retired and reported")
	assert.Zero(t, quotas.value, "idle quota buckets are retired and reported")
}

func TestServingReservationSettleRefusesUnaffordableUnderEstimate(t *testing.T) {
	s := newServingBudget(ServingConfig{Rate: 150, Burst: 150})
	require.True(t, s.reserve("peer", "10.0.0.1", "10.0.0.0", 100))
	r := &servingReservation{
		budget: s, id: "peer", addr: "10.0.0.1", subnet: "10.0.0.0", held: 100,
	}

	// The response turns out to be 200 bytes but only 50 remain, so the extra
	// 100 cannot be acquired. It must be refused rather than charged as debt:
	// once the bytes are handed to the transport no ceiling can take them back.
	require.False(t, r.settle(200), "a response the budget cannot cover must be refused")
	assert.InDelta(t, 100.0, r.held, 1.0, "still holds only what was admitted")

	r.release()
	assert.InDelta(t, 150.0, s.globalAvailable(), 1.0, "the refused response leaves nothing charged")
}

func TestServingReservationSettleAcquiresAffordableUnderEstimate(t *testing.T) {
	s := newServingBudget(ServingConfig{Rate: 1000, Burst: 1000})
	require.True(t, s.reserve("peer", "10.0.0.1", "10.0.0.0", 100))
	r := &servingReservation{
		budget: s, id: "peer", addr: "10.0.0.1", subnet: "10.0.0.0", held: 100,
	}

	require.True(t, r.settle(300), "the extra 200 is available")
	assert.InDelta(t, 700.0, s.globalAvailable(), 1.0, "charged the real size, not the estimate")
}

func TestKeyedBudgetsChargesSurviveConcurrentSweep(t *testing.T) {
	// Exercises the lookup-then-charge window against sweep. Run under -race
	// for the data-race half; the assertion covers the accounting half, since
	// a charge landing on a retired bucket would be lost and let the total
	// admitted exceed the burst.
	const burst = 500
	k := newKeyedBudgets(0.0001, burst) // refill so slow it cannot mask losses

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				k.sweep(time.Now())
			}
		}
	}()

	var mu sync.Mutex
	var admitted float64
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 200; j++ {
				if k.reserve("shared", 10) {
					mu.Lock()
					admitted += 10
					mu.Unlock()
				}
			}
		}()
	}
	workers.Wait()
	close(stop)
	wg.Wait()

	assert.LessOrEqual(t, admitted, float64(burst)+10.0,
		"total admitted must stay within one burst; more means charges were lost to sweep")
}

func TestWithServingConfigOverridesDefaults(t *testing.T) {
	bcR := &Reactor{servingBudget: newServingBudget(DefaultServingConfig())}
	assert.InDelta(t, float64(DefaultServingConfig().Burst), bcR.servingBudget.globalAvailable(), 1.0)

	WithServingConfig(ServingConfig{Rate: 1000, Burst: 1000})(bcR)
	assert.InDelta(t, 1000.0, bcR.servingBudget.globalAvailable(), 1.0,
		"the option replaces the default budget")
}

func TestServingBudgetExemptionIsCaseInsensitive(t *testing.T) {
	// Node IDs are lowercase hex from the handshake, but get copied out of
	// tools and logs that render them uppercase. An exemption written in the
	// wrong case must still match, or the partner it was meant to exempt is
	// silently throttled with nothing logged.
	const lower = "ab12cd34"
	const upper = "AB12CD34"

	for _, tc := range []struct {
		name       string
		configured p2p.ID
	}{
		{"configured lowercase", lower},
		{"configured uppercase", upper},
		{"configured mixed case", "Ab12Cd34"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := servingTestConfig()
			cfg.ExemptIDs = []p2p.ID{tc.configured}
			s := newServingBudget(cfg)

			// The handshake always presents the lowercase form.
			assert.True(t, s.isExempt(lower), "must match the handshake's lowercase ID")
		})
	}

	t.Run("a genuinely different id is still not exempt", func(t *testing.T) {
		cfg := servingTestConfig()
		cfg.ExemptIDs = []p2p.ID{upper}
		s := newServingBudget(cfg)
		assert.False(t, s.isExempt("ffffffff"), "case folding must not make unrelated IDs match")
	})
}
