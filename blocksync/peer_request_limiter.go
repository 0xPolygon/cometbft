package blocksync

import (
	"net"
	"sync"
	"time"

	"github.com/go-kit/kit/metrics"

	"github.com/cometbft/cometbft/p2p"
	bcproto "github.com/cometbft/cometbft/proto/tendermint/blocksync"
)

// blockRequestWindow, maxBlockRequestsPerWindow, and maxIPRequestsPerWindow
// bound how many BlockRequest messages the reactor will service in a rolling
// window, per peer identity and per remote IP respectively. respondToPeer
// reloads state from the store and marshals a full block per request, so an
// unbounded peer can force that cost indefinitely.
//
// maxBlockRequestsPerWindow is calibrated against measured legitimate
// blocksync catch-up throughput, not an assumed nominal number. A single
// catching-up node concentrates its own requests onto one fast peer via
// pickIncrAvailablePeer (up to maxPendingRequestsPerPeer in flight at a
// time), and the pool's own request-creation pacing (requestIntervalMS,
// maxPendingRequestsPerPeer — see pool.go) lets that reach on the order of
// 100+ BlockRequests/sec against a single peer for an ordinary
// node (verified directly against a real blocksync catch-up, not just derived
// from the constants). The per-identity cap has to clear that with real
// margin, or it throttles the exact case it must not affect —
// a fresh or long-offline node's normal catch-up sync.
//
// p2p.ID is cryptographically unforgeable (derived from the peer's
// authenticated public key over the secret handshake) but free to generate:
// a peer can present a new node key per connection and get a fresh
// per-identity window each time, for the cost of one TCP connection and
// handshake. The per-IP limiter exists to make that not worth doing — an
// address is harder to change than a local keypair — without claiming to
// eliminate the pattern, which remains bounded by max_num_inbound_peers and
// achievable handshake rate rather than by this limiter.
//
// The IP limiter keys on ipRateLimitKey's network-prefix bucket (/24 for
// IPv4, /64 for IPv6), not the exact address, so that requests spread across
// many addresses inside one network block are accounted together: each
// address can otherwise stay under budget while the block's aggregate does
// not. It also treats a single routed /64 as one allocation rather than as
// the many distinct addresses it can present. Requests spread across many
// separate prefixes are not constrained by this layer.
//
// maxIPRequestsPerWindow is 3x the per-identity cap. Once the per-identity
// cap sits above what a single-peer catch-up needs, it necessarily also sits
// above what one connection can push at all, since per-connection throughput
// is already bounded by send_rate/recv_rate in config.toml independently of
// this limiter — so no per-identity cap large enough to avoid false positives
// adds throttling for a single connection. The per-prefix layer is the one
// that still binds: a single node is one connection in one bucket, so the cap
// must clear a few of those sharing a bucket (a coordinated restart of
// several nodes behind one NAT or subnet is realistic; an entire regional
// group is not budgeted for here) while still sitting below the aggregate
// many concurrent connections in one block can reach. 3x reserves headroom
// for roughly 2-3 simultaneous catch-ups per bucket without raising the flat
// per-bucket cap so far that concurrent connections clear it too.
//
// Neither counts nor a ban are cleared on disconnect (see allow/sweep): a
// peer that has used up its window, or been banned for exceeding it, must not
// be able to reset either by disconnecting and reconnecting with the same
// identity. Otherwise a peer sitting at the cap could cycle its connection
// for unlimited sustained throughput, and one that exceeds it could do the
// same to skip banDuration entirely.
//
// banDuration is how long an identity/IP that has exceeded its window keeps
// being denied. Equal to blockRequestWindow: reconnecting mid-penalty ends
// up no better (and no worse) off than staying connected.
//
// limiterSweepInterval bounds how long a stale entry can survive after its
// own natural expiry, for a key that never sends another request (so
// allow's lazy per-key cleanup never runs for it). Reused at
// blockRequestWindow's cadence rather than introducing a separate tuning
// knob.
const (
	blockRequestWindow        = 10 * time.Second
	maxBlockRequestsPerWindow = 2000
	maxIPRequestsPerWindow    = 3 * maxBlockRequestsPerWindow
	banDuration               = blockRequestWindow
	limiterSweepInterval      = blockRequestWindow

	// ipv4PrefixBits and ipv6PrefixBits are the network-prefix lengths
	// ipRateLimitKey buckets remote addresses to. /24 and /64 respectively
	// are conventional single-allocation boundaries (a /24 is the smallest
	// commonly-routed IPv4 block; a /64 is the standard single-subnet IPv6
	// allocation), chosen so the bucket tracks "one plausible network
	// operator" rather than "one address."
	ipv4PrefixBits = 24
	ipv6PrefixBits = 64

	// persistentPeerExemptionHeight gates when a peer we've explicitly
	// configured via persistent_peers starts bypassing both rate limiters
	// entirely for its own requests (see exemptFromRateLimit). Both caps
	// above are sized to clear measured legitimate single-peer catch-up
	// with margin, which means they also can't meaningfully throttle a
	// single connection below what CometBFT's own send_rate/
	// recv_rate byte cap already limits it to — that overlap is
	// unavoidable for any peer this node has no other way to vouch for.
	// A persistent peer is different: IsPersistent() for an inbound
	// connection is tied to the peer's authenticated node ID from the
	// secret handshake matching a configured persistent_peers entry, not
	// something a remote peer can claim its way into. Exempting it is
	// exactly as safe as trusting persistent_peers itself already is.
	//
	// This height is a local, per-node rollout gate, not a consensus
	// hardfork: it only changes how this node answers p2p requests, never
	// what it accepts into its own chain state, so mismatched activation
	// across different nodes has no consensus-safety implication. Set to
	// 0 for immediate activation (e.g. on Amoy, to validate the feature
	// before mainnet); raise it to defer activation until a coordinated
	// rollout height is reached everywhere.
	persistentPeerExemptionHeight int64 = 0
)

// exemptFromRateLimit reports whether src's own requests should bypass both
// the per-identity and per-subnet rate limiters entirely, given the node's
// current height. See persistentPeerExemptionHeight's doc comment for why
// this is safe to trust and why the height gate isn't a consensus concern.
func exemptFromRateLimit(src p2p.Peer, currentHeight int64) bool {
	return currentHeight >= persistentPeerExemptionHeight && src.IsPersistent()
}

// allowBlockRequest reports whether respondToPeer should serve msg from src:
// exempt persistent peers bypass both limiters outright, everyone else is
// checked per identity then per subnet, in that order (either can deny).
// Extracted out of respondToPeer to keep that function's branching (and
// reactor.go's size) within diffguard's budget.
//
// The subnet-ban precheck runs before the peer limiter touches anything:
// without it, an already-subnet-banned peer could present a fresh p2p.ID
// per connection and, even though every one of those requests is doomed to
// be denied by the subnet ban, still force the peer limiter to allocate a
// new window entry per attempt for the rest of the ban's duration — turning
// the subnet layer's own identity-rotation defense into unbounded
// remotely-driven map growth on our side. Checking peer-then-subnet
// order otherwise (once past this precheck) is still fine: a request the
// peer limiter denies never reaches the subnet check at all, so it was
// never able to charge the subnet's budget in the first place.
func allowBlockRequest(bcR *Reactor, src p2p.Peer, msg *bcproto.BlockRequest) bool {
	if exemptFromRateLimit(src, bcR.store.Height()) {
		bcR.metrics.PersistentPeerRequestsExempted.Add(1)
		return true
	}
	if bcR.ipLimiter.isBanned(ipRateLimitKey(src.RemoteIP())) {
		bcR.metrics.SubnetBlockRequestsDropped.Add(1)
		return false
	}
	if !checkRateLimit(bcR, bcR.reqLimiter, src.ID(), bcR.metrics.PeerBlockRequestsDropped,
		"peer exceeded block-sync request rate, banning further requests until ban expires", "peer", msg) {
		return false
	}
	return checkRateLimit(bcR, bcR.ipLimiter, ipRateLimitKey(src.RemoteIP()), bcR.metrics.SubnetBlockRequestsDropped,
		"remote subnet exceeded block-sync request rate, banning further requests until ban expires", "subnet", msg)
}

// requestLimiter tracks, per key K (a peer identity or a remote IP), how
// many BlockRequest messages have been serviced in the current window,
// plus any active ban from a prior over-limit window.
type requestLimiter[K comparable] struct {
	mtx         sync.Mutex
	counts      map[K]*requestWindow
	bannedUntil map[K]time.Time
	maxRequests int
}

type requestWindow struct {
	// timestamps holds one entry per request currently counted against
	// the trailing blockRequestWindow-sized interval ending "now", oldest
	// first. allow never lets it grow past maxRequests entries, so memory
	// per tracked key is bounded regardless of how long a peer stays
	// connected.
	timestamps []time.Time
	// warned is set the first time a key exceeds the limit while its
	// window is non-empty, so respondToPeer logs once per over-limit
	// episode instead of once per dropped request. Cleared once the
	// window fully empties (see evictExpired), so a fresh episode after a
	// genuine idle gap is logged again rather than staying suppressed.
	warned bool
}

func newRequestLimiter[K comparable](maxRequests int) *requestLimiter[K] {
	return &requestLimiter[K]{
		counts:      make(map[K]*requestWindow),
		bannedUntil: make(map[K]time.Time),
		maxRequests: maxRequests,
	}
}

// isBanned reports whether key currently has an active (unexpired) ban.
// Unlike allow, this never mutates l's state — it exists so a caller
// juggling more than one limiter can check ban status up front and skip
// the other limiter entirely for an already-doomed request, instead of
// letting that limiter record a window entry for a request this one was
// always going to deny anyway (see allowBlockRequest).
func (l *requestLimiter[K]) isBanned(key K) bool {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	until, banned := l.bannedUntil[key]
	return banned && time.Now().Before(until)
}

func newPeerBlockRequestLimiter() *requestLimiter[p2p.ID] {
	return newRequestLimiter[p2p.ID](maxBlockRequestsPerWindow)
}

func newIPBlockRequestLimiter() *requestLimiter[string] {
	return newRequestLimiter[string](maxIPRequestsPerWindow)
}

// ipRateLimitKey buckets ip to its /24 (IPv4) or /64 (IPv6) network prefix
// — see the const block above for why a prefix rather than the exact
// address. net.IP.Mask never panics on a nil or malformed IP; it returns
// nil, which String()s to "<nil>", grouping any such input into one shared
// (harmless) bucket rather than crashing.
func ipRateLimitKey(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.Mask(net.CIDRMask(ipv4PrefixBits, 32)).String()
	}
	if ip16 := ip.To16(); ip16 != nil {
		return ip16.Mask(net.CIDRMask(ipv6PrefixBits, 128)).String()
	}
	return ip.String()
}

// allow reports whether a BlockRequest under key should be serviced right
// now. See allowAt, which it delegates to with the real clock — split out
// so tests can exercise the exact same rate-limiting logic against
// controlled timestamps instead of duplicating it.
func (l *requestLimiter[K]) allow(key K) (ok bool, justExceeded bool) {
	return l.allowAt(key, time.Now())
}

// allowAt reports whether a BlockRequest under key should be serviced as of
// now and, if so, records now against that key's trailing window as a side
// effect. justExceeded is true only on the request that first crosses the
// limit while the window is non-empty, so callers can log once instead of
// per dropped request.
func (l *requestLimiter[K]) allowAt(key K, now time.Time) (ok bool, justExceeded bool) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if until, banned := l.bannedUntil[key]; banned {
		if now.Before(until) {
			return false, false
		}
		delete(l.bannedUntil, key)
	}

	w, exists := l.counts[key]
	if !exists {
		w = &requestWindow{}
		l.counts[key] = w
	}
	w.evictExpired(now)

	if len(w.timestamps) < l.maxRequests {
		w.timestamps = append(w.timestamps, now)
		return true, false
	}
	if !w.warned {
		w.warned = true
		l.bannedUntil[key] = now.Add(banDuration)
		return false, true
	}
	return false, false
}

// evictExpired drops every timestamp older than blockRequestWindow relative
// to now, leaving w.timestamps an exact record of requests within the
// trailing rolling window rather than an approximation of one — a request
// distributed unevenly across two adjacent fixed windows can't hide from
// this the way it could from a windowed-counter approximation (see git
// history: an earlier version of this limiter approximated the rolling
// window with two adjacent fixed windows and a decay-weighted estimate,
// which closed the sharp boundary-doubling case but still under-counted a
// request pattern clustered late in each fixed window; this replaced it).
// Resets warned once the window is fully empty, so a fresh over-limit
// episode after a genuine idle gap is logged again instead of staying
// silently suppressed by a stale warning from a prior episode.
func (w *requestWindow) evictExpired(now time.Time) {
	cutoff := now.Add(-blockRequestWindow)
	i := 0
	for i < len(w.timestamps) && w.timestamps[i].Before(cutoff) {
		i++
	}
	w.timestamps = w.timestamps[i:]
	if len(w.timestamps) == 0 {
		w.warned = false
	}
}

// sweep deletes any window or ban entry that has fully expired as of now —
// a window entry once every timestamp in it has aged out of the trailing
// window, a ban once it's past its own deadline. It's the only cleanup
// mechanism for both maps — neither is tied to peer connection lifecycle,
// so a key that stops sending requests (whether its peer disconnected or
// just went quiet) doesn't leave state behind indefinitely. Called
// periodically by the reactor, not on every request, so steady-state map
// size lags real expiry by at most one sweep interval.
func (l *requestLimiter[K]) sweep(now time.Time) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	for key, w := range l.counts {
		w.evictExpired(now)
		if len(w.timestamps) == 0 {
			delete(l.counts, key)
		}
	}
	for key, until := range l.bannedUntil {
		if !now.Before(until) {
			delete(l.bannedUntil, key)
		}
	}
}

// sizes reports the current number of tracked window and ban entries.
// Read alongside sweep so the exported gauges reflect post-cleanup
// steady state rather than a transient peak — this is the map-size
// observability neither map had while cleanup was tied to disconnect,
// so growth from removing that tie is visible instead of assumed-bounded.
func (l *requestLimiter[K]) sizes() (windows, bans int) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	return len(l.counts), len(l.bannedUntil)
}

// limiterSweepRoutine periodically sweeps both rate limiters and reports
// their post-sweep sizes. Runs regardless of bcR.blockSync, since
// respondToPeer (and thus both limiters) serves other peers' catch-up
// requests whether or not this node is itself syncing.
//
// Selects on bcR.sweepStopCh rather than bcR.Quit(): BaseService.Stop calls
// OnStop before closing the reactor's own quit channel, so waiting on
// bcR.Quit() here would deadlock OnStop's WaitGroup.Wait forever.
func (bcR *Reactor) limiterSweepRoutine() {
	ticker := time.NewTicker(limiterSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-bcR.sweepStopCh:
			return
		case <-ticker.C:
			now := time.Now()
			sweepAndReport(bcR.reqLimiter, now, bcR.metrics.PeerLimiterWindows, bcR.metrics.PeerLimiterBans)
			sweepAndReport(bcR.ipLimiter, now, bcR.metrics.SubnetLimiterWindows, bcR.metrics.SubnetLimiterBans)
			sweepServingBudget(bcR.servingBudget, now, bcR.metrics.ServingBudgetTokens,
				bcR.metrics.ServingSubnetBudgets, bcR.metrics.ServingPeerQuotas)
		}
	}
}

func sweepAndReport[K comparable](l *requestLimiter[K], now time.Time, windowsGauge, bansGauge metrics.Gauge) {
	l.sweep(now)
	windows, bans := l.sizes()
	windowsGauge.Set(float64(windows))
	bansGauge.Set(float64(bans))
}

// checkRateLimit reports whether a request keyed by key is within
// limiter's budget, incrementing dropped and logging once per key per
// window when it first crosses the limit. Shared by respondToPeer's
// per-identity and per-remote-IP checks so the near-identical
// check/count/log logic isn't duplicated per limiter.
func checkRateLimit[K comparable](
	bcR *Reactor, limiter *requestLimiter[K], key K, dropped metrics.Counter,
	logMsg, keyField string, msg *bcproto.BlockRequest,
) bool {
	ok, justExceeded := limiter.allow(key)
	if ok {
		return true
	}
	dropped.Add(1)
	if justExceeded {
		bcR.Logger.Error(logMsg,
			keyField, key, "height", msg.Height, "window", blockRequestWindow, "limit", limiter.maxRequests, "banDuration", banDuration)
	}
	return false
}
