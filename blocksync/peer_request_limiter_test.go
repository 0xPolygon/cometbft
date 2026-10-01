package blocksync

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/p2p"
	p2pmock "github.com/cometbft/cometbft/p2p/mock"
)

func TestPeerBlockRequestLimiter_AllowsUpToLimit(t *testing.T) {
	l := newPeerBlockRequestLimiter()
	peer := p2p.ID("peer-1")

	for i := range maxBlockRequestsPerWindow {
		ok, justExceeded := l.allow(peer)
		require.True(t, ok, "request %d should be allowed", i)
		require.False(t, justExceeded)
	}
}

func TestPeerBlockRequestLimiter_DropsOverLimit(t *testing.T) {
	l := newPeerBlockRequestLimiter()
	peer := p2p.ID("peer-1")

	for range maxBlockRequestsPerWindow {
		_, _ = l.allow(peer)
	}

	ok, justExceeded := l.allow(peer)
	require.False(t, ok)
	require.True(t, justExceeded, "first drop in a window should report justExceeded")

	ok, justExceeded = l.allow(peer)
	require.False(t, ok)
	require.False(t, justExceeded, "subsequent drops in the same window should not re-report justExceeded")
}

func TestPeerBlockRequestLimiter_IndependentPerPeer(t *testing.T) {
	l := newPeerBlockRequestLimiter()
	a, b := p2p.ID("peer-a"), p2p.ID("peer-b")

	for range maxBlockRequestsPerWindow {
		_, _ = l.allow(a)
	}
	ok, _ := l.allow(a)
	require.False(t, ok, "peer a should be limited")

	ok, _ = l.allow(b)
	require.True(t, ok, "peer b should be unaffected by peer a's usage")
}

func TestPeerBlockRequestLimiter_ResetsAfterWindow(t *testing.T) {
	l := newPeerBlockRequestLimiter()
	peer := p2p.ID("peer-1")

	l.mtx.Lock()
	l.counts[peer] = &requestWindow{
		timestamps: []time.Time{time.Now().Add(-blockRequestWindow - time.Second)},
		warned:     true,
	}
	l.mtx.Unlock()

	ok, justExceeded := l.allow(peer)
	require.True(t, ok, "request after the sole timestamp ages out of the window should be allowed again")
	require.False(t, justExceeded)
}

func TestPeerBlockRequestLimiter_Sweep_RemovesExpiredWindowAndBan(t *testing.T) {
	l := newPeerBlockRequestLimiter()
	expired, active := p2p.ID("peer-expired"), p2p.ID("peer-active")

	l.mtx.Lock()
	l.counts[expired] = &requestWindow{timestamps: []time.Time{time.Now().Add(-blockRequestWindow - time.Second)}}
	l.counts[active] = &requestWindow{timestamps: []time.Time{time.Now()}}
	l.bannedUntil[expired] = time.Now().Add(-time.Second)
	l.bannedUntil[active] = time.Now().Add(banDuration)
	l.mtx.Unlock()

	l.sweep(time.Now())

	l.mtx.Lock()
	_, countExists := l.counts[expired]
	_, banExists := l.bannedUntil[expired]
	_, activeCountExists := l.counts[active]
	_, activeBanExists := l.bannedUntil[active]
	l.mtx.Unlock()

	require.False(t, countExists, "sweep should remove an expired window")
	require.False(t, banExists, "sweep should remove an expired ban")
	require.True(t, activeCountExists, "sweep must not remove a still-active window")
	require.True(t, activeBanExists, "sweep must not remove a still-active ban")
}

func TestPeerBlockRequestLimiter_Sizes(t *testing.T) {
	l := newPeerBlockRequestLimiter()

	windows, bans := l.sizes()
	require.Equal(t, 0, windows)
	require.Equal(t, 0, bans)

	_, _ = l.allow(p2p.ID("peer-a"))
	_, _ = l.allow(p2p.ID("peer-b"))
	for range maxBlockRequestsPerWindow + 1 {
		_, _ = l.allow(p2p.ID("peer-c"))
	}

	windows, bans = l.sizes()
	require.Equal(t, 3, windows, "one window entry per distinct peer that has sent a request")
	require.Equal(t, 1, bans, "only peer-c exceeded its window and earned a ban")
}

func TestPeerBlockRequestLimiter_BanSurvivesSweep_UntilItExpires(t *testing.T) {
	l := newPeerBlockRequestLimiter()
	peer := p2p.ID("peer-1")

	for range maxBlockRequestsPerWindow {
		_, _ = l.allow(peer)
	}
	ok, justExceeded := l.allow(peer)
	require.False(t, ok)
	require.True(t, justExceeded)

	// A sweep run while the ban is still active must not lift it — only
	// forgetting/disconnecting used to do that (the bug this fix closes);
	// sweep must only ever reclaim state that has already naturally expired.
	l.sweep(time.Now())

	ok, justExceeded = l.allow(peer)
	require.False(t, ok, "an unexpired ban must survive a sweep")
	require.False(t, justExceeded)
}

func TestPeerBlockRequestLimiter_BanExpiresAfterBanDuration(t *testing.T) {
	l := newPeerBlockRequestLimiter()
	peer := p2p.ID("peer-1")

	l.mtx.Lock()
	l.bannedUntil[peer] = time.Now().Add(-time.Second)
	l.mtx.Unlock()

	ok, justExceeded := l.allow(peer)
	require.True(t, ok, "request after the ban expires should be allowed again")
	require.False(t, justExceeded)

	l.mtx.Lock()
	_, stillBanned := l.bannedUntil[peer]
	l.mtx.Unlock()
	require.False(t, stillBanned, "an expired ban should be cleared on next access")
}

func TestEvictExpired_DropsOnlyTimestampsOlderThanTheWindow(t *testing.T) {
	now := time.Now()
	w := &requestWindow{
		warned: true,
		timestamps: []time.Time{
			now.Add(-blockRequestWindow - time.Second), // expired
			now.Add(-blockRequestWindow + time.Second), // still in window
			now,
		},
	}

	w.evictExpired(now)

	require.Len(t, w.timestamps, 2, "only the timestamp older than the window should be dropped")
	require.True(t, w.warned, "warned must survive while the window is still non-empty")
}

func TestEvictExpired_ClearsWarnedOnceWindowFullyEmpties(t *testing.T) {
	now := time.Now()
	w := &requestWindow{
		warned:     true,
		timestamps: []time.Time{now.Add(-blockRequestWindow - time.Second)},
	}

	w.evictExpired(now)

	require.Empty(t, w.timestamps)
	require.False(t, w.warned, "warned must clear once every timestamp has aged out")
}

// TestRequestLimiter_AllowAt_EnforcesExactRollingWindowAcrossUnevenBursts is
// the regression test for the gap in the prior two-fixed-window
// approximation that Copilot's second review round caught: it under-counted
// a request pattern clustered late within each fixed window, letting close
// to 2x the documented cap land inside one real trailing window. Drives
// requests through three sub-bursts positioned the same way Copilot's
// review comment specified (near the end of one fixed window, then twice
// more within the next), and asserts the total served within the last
// blockRequestWindow interval never exceeds maxBlockRequestsPerWindow —
// the property an exact timestamp log guarantees by construction, which no
// counter-based approximation can.
func TestRequestLimiter_AllowAt_EnforcesExactRollingWindowAcrossUnevenBursts(t *testing.T) {
	l := newPeerBlockRequestLimiter()
	peer := p2p.ID("peer-1")
	base := time.Now().Add(-30 * time.Second)

	var served []time.Time
	burst := func(at time.Time, n int) {
		for range n {
			if ok, _ := l.allowAt(peer, at); ok {
				served = append(served, at)
			}
		}
	}

	burst(base.Add(9*time.Second+990*time.Millisecond), maxBlockRequestsPerWindow-1)  // t=9.99s, near the end of one fixed window
	burst(base.Add(15*time.Second), maxBlockRequestsPerWindow/2)                      // t=15s, into the next
	burst(base.Add(19*time.Second+980*time.Millisecond), maxBlockRequestsPerWindow/2) // t=19.98s

	trailingWindowEnd := served[len(served)-1]
	inTrailingWindow := 0
	for _, ts := range served {
		if !ts.Before(trailingWindowEnd.Add(-blockRequestWindow)) {
			inTrailingWindow++
		}
	}

	require.LessOrEqual(t, inTrailingWindow, maxBlockRequestsPerWindow,
		"an exact rolling window must never allow more than the documented cap within any trailing blockRequestWindow interval, even when requests are spread unevenly across fixed-window boundaries")
}

func TestIPBlockRequestLimiter_CapsAcrossDistinctKeys(t *testing.T) {
	l := newIPBlockRequestLimiter()
	ip := "203.0.113.7"

	for i := 0; i < maxIPRequestsPerWindow; i++ {
		ok, _ := l.allow(ip)
		require.True(t, ok, "request %d should be allowed", i)
	}

	ok, justExceeded := l.allow(ip)
	require.False(t, ok, "request beyond the IP-level limit should be dropped")
	require.True(t, justExceeded)
}

func TestIPBlockRequestLimiter_IndependentPerIP(t *testing.T) {
	l := newIPBlockRequestLimiter()
	a, b := "203.0.113.7", "198.51.100.9"

	for range maxIPRequestsPerWindow {
		_, _ = l.allow(a)
	}
	ok, _ := l.allow(a)
	require.False(t, ok, "IP a should be limited")

	ok, _ = l.allow(b)
	require.True(t, ok, "IP b should be unaffected by IP a's usage")
}

func TestIPBlockRequestLimiter_HigherCapThanPeerLimiter(t *testing.T) {
	require.Greater(t, maxIPRequestsPerWindow, maxBlockRequestsPerWindow,
		"the IP-level cap must sit above the per-identity cap, or a single legitimate peer would be throttled by IP before hitting its own identity limit")
}

func TestIPRateLimitKey_BucketsIPv4BySlash24(t *testing.T) {
	// Many distinct addresses inside one /24 must share a bucket — the
	// scenario a per-exact-address key can't defend against.
	require.Equal(t,
		ipRateLimitKey(net.ParseIP("203.0.113.5")),
		ipRateLimitKey(net.ParseIP("203.0.113.250")),
		"addresses in the same /24 must map to the same bucket")

	require.NotEqual(t,
		ipRateLimitKey(net.ParseIP("203.0.113.5")),
		ipRateLimitKey(net.ParseIP("198.51.100.5")),
		"addresses in different /24s must map to different buckets")
}

func TestIPRateLimitKey_IPv4MappedIPv6MatchesPlainIPv4(t *testing.T) {
	// An attacker must not be able to split its budget by presenting the
	// same real address in two different string forms.
	require.Equal(t,
		ipRateLimitKey(net.ParseIP("203.0.113.5")),
		ipRateLimitKey(net.ParseIP("::ffff:203.0.113.5")),
		"an IPv4 address and its IPv4-mapped-IPv6 form must bucket identically")
}

func TestIPRateLimitKey_BucketsIPv6BySlash64(t *testing.T) {
	require.Equal(t,
		ipRateLimitKey(net.ParseIP("2001:db8:1234:5678::1")),
		ipRateLimitKey(net.ParseIP("2001:db8:1234:5678:ffff:ffff:ffff:ffff")),
		"addresses in the same /64 must map to the same bucket")

	require.NotEqual(t,
		ipRateLimitKey(net.ParseIP("2001:db8:1234:5678::1")),
		ipRateLimitKey(net.ParseIP("2001:db8:1234:5679::1")),
		"addresses in different /64s must map to different buckets")
}

func TestIPBlockRequestLimiter_CapsAcrossSharedSubnet(t *testing.T) {
	l := newIPBlockRequestLimiter()
	// Distinct exact addresses, same /24 — the pattern a per-exact-address
	// key can't defend against (none individually hits an exact-IP cap).
	subnet := []string{"203.0.113.5", "203.0.113.9", "203.0.113.250"}

	served := 0
	for served < maxIPRequestsPerWindow {
		key := ipRateLimitKey(net.ParseIP(subnet[served%len(subnet)]))
		ok, _ := l.allow(key)
		require.True(t, ok, "request %d (distinct address, shared /24) within the bucket limit should be served", served)
		served++
	}

	key := ipRateLimitKey(net.ParseIP("203.0.113.99"))
	ok, _ := l.allow(key)
	require.False(t, ok, "a fourth distinct address in an already-capped /24 must still be denied")
}

func TestExemptFromRateLimit_PersistentPeerAtOrPastActivationHeight(t *testing.T) {
	peer := p2pmock.NewPeer(nil)
	peer.Persistent = true
	defer peer.Stop() //nolint:errcheck

	require.True(t, exemptFromRateLimit(peer, persistentPeerExemptionHeight),
		"a persistent peer at the activation height must be exempt")
	require.True(t, exemptFromRateLimit(peer, persistentPeerExemptionHeight+1000),
		"a persistent peer well past the activation height must be exempt")
}

func TestExemptFromRateLimit_NonPersistentPeerNeverExempt(t *testing.T) {
	peer := p2pmock.NewPeer(nil)
	peer.Persistent = false
	defer peer.Stop() //nolint:errcheck

	require.False(t, exemptFromRateLimit(peer, persistentPeerExemptionHeight+1000),
		"a non-persistent peer must never be exempt, regardless of height")
}

func TestExemptFromRateLimit_PersistentPeerBeforeActivationHeight(t *testing.T) {
	peer := p2pmock.NewPeer(nil)
	peer.Persistent = true
	defer peer.Stop() //nolint:errcheck

	require.False(t, exemptFromRateLimit(peer, persistentPeerExemptionHeight-1),
		"a persistent peer must not be exempt before the activation height, even at height 0 by default this only matters once the constant is raised above 0")
}

func TestRequestLimiter_IsBanned_TrueOnlyWhileUnexpired(t *testing.T) {
	l := newPeerBlockRequestLimiter()
	peer := p2p.ID("peer-1")

	require.False(t, l.isBanned(peer), "a key with no ban entry at all must not read as banned")

	l.mtx.Lock()
	l.bannedUntil[peer] = time.Now().Add(banDuration)
	l.mtx.Unlock()
	require.True(t, l.isBanned(peer), "a key with an active, unexpired ban must read as banned")

	l.mtx.Lock()
	l.bannedUntil[peer] = time.Now().Add(-time.Second)
	l.mtx.Unlock()
	require.False(t, l.isBanned(peer), "a key whose ban has already expired must not read as banned")
}

func TestRequestLimiter_IsBanned_DoesNotMutateState(t *testing.T) {
	l := newPeerBlockRequestLimiter()
	peer := p2p.ID("peer-1")

	require.False(t, l.isBanned(peer))

	windows, bans := l.sizes()
	require.Equal(t, 0, windows, "isBanned must never create a window entry as a side effect")
	require.Equal(t, 0, bans, "isBanned must never create a ban entry as a side effect")
}
