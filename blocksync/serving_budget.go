package blocksync

import (
	"math"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/metrics"

	"github.com/cometbft/cometbft/p2p"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

// The limiters in peer_request_limiter.go bound how many BlockRequests this
// node answers. They do not bound how many bytes those answers cost, which is
// a different quantity: a request count sized to leave a legitimate catch-up
// unthrottled still authorizes several MB/s per peer once multiplied by block
// size, and outbound bytes are what a node operator actually pays for and
// provisions bandwidth against.
//
// Three layers, because they bound different things and none is sufficient
// alone:
//
//  1. A node-wide rate ceiling. Makes total outbound block-sync cost a
//     configured constant rather than a function of how many peers happen to
//     be requesting. No per-peer limit can do this, since the number of peers
//     is not something this node chooses.
//
//  2. A per-network-prefix share of that ceiling. Without it the node-wide
//     budget is still bounded but handed out first-come-first-served, so the
//     fastest requester takes all of it and other peers see none, inside a
//     ceiling that is technically being respected. Keyed on ipRateLimitKey's
//     prefix rather than on p2p.ID deliberately: a node ID is free to
//     generate, so a per-identity share can be multiplied at will, whereas
//     address space has to be obtained.
//
//  3. A per-address volume quota. The rate layers bound speed; this one
//     bounds how much one address can draw over time, so continuous
//     high-volume serving to a single source is capped no matter how slowly
//     it is drawn.
//
//     Implemented as a token bucket refilling at quota/period with a burst of
//     quota, which is an average-rate-plus-burst control, not a strict
//     sliding window. Be precise about what that bounds: the long-run average
//     converges to quota per period, but one period-length window can contain
//     up to 2x quota — drain the burst at the start, wait a period for it to
//     refill, drain it again. A strict sliding window would need a
//     timestamped record of every charge, as the request limiter keeps for
//     request counts; for bytes that is thousands of entries per address per
//     period, and the 2x worst case is not worth the memory. Size the quota
//     knowing the bound is 2x, not 1x.
//
// The quota period is deliberately short — an hour by default rather than a
// day. A longer period would have to survive process restarts to mean
// anything, since an in-memory counter resets with the process; an hourly
// window gives equivalent containment per day, tolerates restarts by
// construction, and needs no on-disk accounting.
//
// Persistent peers bypass all three, as they bypass the request limiters —
// see exemptFromRateLimit. Configured exempt peers (ExemptIDs, for known
// operators running large legitimate syncs) bypass layers 2 and 3 but are
// still counted against layer 1: an exemption should mean "not rate-shared
// and not quota-capped", never "may spend this node's entire budget".
//
// Scope, so the guarantee is not overstated: this bounds bytes served from
// this reactor. It does not limit connections, does not change how inbound
// slots are allocated, and does not keep catch-up fast for an unexempted peer
// once the budget is saturated — such a peer is served more slowly, and may
// be served not at all while the budget is spent. What it provides is that
// the total is a number chosen in config rather than one set by demand.

// ReactorOption adjusts optional Reactor behavior. It exists so serving
// limits can be supplied without changing NewReactor/NewReactorWithAddr's
// signatures, which are exported and which downstream callers compile
// against — a reactor constructed without any option keeps
// DefaultServingConfig.
type ReactorOption func(*Reactor)

// WithServingConfig sets the block-sync serving limits for a reactor.
func WithServingConfig(cfg ServingConfig) ReactorOption {
	return func(bcR *Reactor) {
		bcR.servingBudget = newServingBudget(cfg)
	}
}

// ServingConfig is the blocksync-serving policy, translated from
// config.BlockSyncConfig by the node wiring. Kept local to this package so
// the package stays independently testable and takes no dependency on the
// config package. A zero value in any field disables that layer.
type ServingConfig struct {
	// Rate and Burst bound node-wide bytes per second served to
	// non-persistent peers. Burst defaults to two seconds of Rate.
	Rate  float64
	Burst float64
	// SubnetRate caps one remote network prefix, in bytes per second.
	SubnetRate float64
	// Quota is one remote address's token-bucket capacity in bytes. Tokens
	// refill over QuotaPeriod, allowing up to 2x Quota in a period-length
	// interval while converging to Quota per period over the long run.
	Quota       float64
	QuotaPeriod time.Duration
	// ExemptIDs bypass SubnetRate and Quota but not Rate.
	ExemptIDs []p2p.ID
}

// DefaultServingConfig mirrors config.DefaultBlockSyncConfig's serving
// values, for callers that construct a reactor without a parsed config.
//
// A quota-exhausted peer continues to be served at the refill rate, so
// quota/period is also a floor: 512 MiB/hour refills at roughly 145 KB/s,
// only modestly above the rate below which a syncing client gives up on a
// peer and disconnects it (minRecvRate, 128 KB/s — see pool.go). An exhausted
// peer will therefore tend to be dropped and re-added rather than degrade
// smoothly, which is an accepted trade: it sheds that peer onto other sources
// instead of letting one address hold a share of this node indefinitely.
// Raising the quota is the lever if smooth degradation is wanted instead.
func DefaultServingConfig() ServingConfig {
	return ServingConfig{
		Rate:        32 << 20,
		Burst:       64 << 20,
		SubnetRate:  8 << 20,
		Quota:       512 << 20,
		QuotaPeriod: time.Hour,
	}
}

const (
	// estimatedResponseBytes is charged before a block is loaded and
	// reconciled against the real size once known. Admission has to
	// precede the work or the store read and the marshal still land, which
	// is the cheaper half of serving one. Set above a typical block so the
	// estimate is rarely low.
	estimatedResponseBytes = 128 << 10

	// blockResponseOverheadBytes covers the protobuf envelope and channel
	// framing around a block and its extended commit, so the budget tracks
	// wire cost rather than payload cost.
	blockResponseOverheadBytes = 1 << 10
)

// byteBudget is a token bucket measured in bytes. Tokens may go negative:
// settle charges a response's real size after an estimate was already
// admitted, and an under-estimate has to be paid rather than silently
// forgiven, so the debt is carried and refilled off.
type byteBudget struct {
	mtx    sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newByteBudget(rate, burst float64) *byteBudget {
	return &byteBudget{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

// reserve deducts n tokens if at least n are available, reporting whether it
// did. Delegates to reserveAt with the real clock so tests can drive the same
// accounting from controlled timestamps.
func (b *byteBudget) reserve(n float64) bool {
	return b.reserveAt(n, time.Now())
}

func (b *byteBudget) reserveAt(n float64, now time.Time) bool {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.refillLocked(now)
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// settle applies the difference between a response's real size and what was
// reserved for it: a positive delta is an extra charge, a negative one a
// refund.
func (b *byteBudget) settle(delta float64) {
	b.settleAt(delta, time.Now())
}

func (b *byteBudget) settleAt(delta float64, now time.Time) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.refillLocked(now)
	b.tokens = math.Min(b.burst, b.tokens-delta)
}

// release returns n reserved-but-unspent tokens, capped at burst so a release
// cannot manufacture capacity beyond the bucket's size.
func (b *byteBudget) release(n float64) {
	b.settle(-n)
}

// available reports the current token count, for metrics. Never above burst,
// and may be negative (see byteBudget).
func (b *byteBudget) available() float64 {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.refillLocked(time.Now())
	return b.tokens
}

// full reports whether nothing has been charged against the bucket recently,
// which is what makes an idle keyed bucket safe to retire.
func (b *byteBudget) full(now time.Time) bool {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.refillLocked(now)
	return b.tokens >= b.burst
}

func (b *byteBudget) refillLocked(now time.Time) {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed <= 0 {
		return
	}
	b.last = now
	b.tokens = math.Min(b.burst, b.tokens+elapsed*b.rate)
}

// keyedBudgets is a lazily-populated set of identical byteBudgets, one per
// key. A zero rate makes every operation a no-op, which is how a disabled
// layer is expressed without branching at each call site.
type keyedBudgets struct {
	rate  float64
	burst float64

	mtx      sync.Mutex
	budgets  map[string]*byteBudget
	disabled bool
}

func newKeyedBudgets(rate, burst float64) *keyedBudgets {
	return &keyedBudgets{
		rate:     rate,
		burst:    burst,
		budgets:  make(map[string]*byteBudget),
		disabled: rate <= 0 || burst <= 0,
	}
}

// reserve and settle hold the map lock across both the lookup and the bucket
// operation, rather than looking the bucket up and releasing the lock first.
// Otherwise sweep can retire a bucket in between and the charge lands on an
// object no later caller will ever consult again, losing it: the retired
// bucket was full, so no debt is erased and no allowance is handed back, but
// the bytes charged against it stop being counted. The window is a few
// instructions wide and hard to hit on purpose; it is closed anyway because
// this is accounting and "hard to hit" is not the same as "cannot happen".
//
// Lock order is map then bucket, matching sweep, so the nesting cannot
// deadlock.
func (k *keyedBudgets) reserve(key string, n float64) bool {
	if k.disabled {
		return true
	}
	k.mtx.Lock()
	defer k.mtx.Unlock()

	return k.getLocked(key).reserve(n)
}

func (k *keyedBudgets) settle(key string, delta float64) {
	if k.disabled {
		return
	}
	k.mtx.Lock()
	defer k.mtx.Unlock()

	k.getLocked(key).settle(delta)
}

// get looks a bucket up, creating it if absent. Callers that then operate on
// the returned bucket race sweep (see reserve); it exists for tests and for
// callers that only read.
func (k *keyedBudgets) get(key string) *byteBudget {
	k.mtx.Lock()
	defer k.mtx.Unlock()

	return k.getLocked(key)
}

func (k *keyedBudgets) getLocked(key string) *byteBudget {
	if b, ok := k.budgets[key]; ok {
		return b
	}
	b := newByteBudget(k.rate, k.burst)
	k.budgets[key] = b
	return b
}

// sweep retires buckets that have refilled to capacity. A key that stops
// requesting leaves nothing behind, which is what bounds the map against a
// requester rotating through address space — the same reason the request
// limiters are swept rather than cleaned up on disconnect. A bucket that is
// still in debt is never retired, so retiring one can never hand out a fresh
// allowance.
func (k *keyedBudgets) sweep(now time.Time) {
	k.mtx.Lock()
	defer k.mtx.Unlock()

	for key, b := range k.budgets {
		if b.full(now) {
			delete(k.budgets, key)
		}
	}
}

func (k *keyedBudgets) size() int {
	k.mtx.Lock()
	defer k.mtx.Unlock()

	return len(k.budgets)
}

// servingBudget is the node-wide ceiling, the per-prefix share of it, and the
// per-address volume quota. All applicable layers must admit a response.
type servingBudget struct {
	global    *byteBudget
	subnets   *keyedBudgets
	quotas    *keyedBudgets
	exemptIDs map[p2p.ID]struct{}
}

func newServingBudget(cfg ServingConfig) *servingBudget {
	burst := cfg.Burst
	if burst <= 0 {
		burst = 2 * cfg.Rate
	}
	global := newByteBudget(cfg.Rate, burst)
	if cfg.Rate <= 0 {
		global = nil
	}
	return &servingBudget{
		global:    global,
		subnets:   newKeyedBudgets(cfg.SubnetRate, 2*cfg.SubnetRate),
		quotas:    newKeyedBudgets(quotaRate(cfg), cfg.Quota),
		exemptIDs: exemptIDSet(cfg.ExemptIDs),
	}
}

// quotaRate expresses the volume quota as a refill rate, so the bucket meters
// it out continuously rather than resetting on a fixed period boundary. Note
// this is an average rate plus a burst of one full quota, not a strict window
// over QuotaPeriod — see the package comment for the 2x bound that implies.
func quotaRate(cfg ServingConfig) float64 {
	if cfg.Quota <= 0 || cfg.QuotaPeriod <= 0 {
		return 0
	}
	return cfg.Quota / cfg.QuotaPeriod.Seconds()
}

func exemptIDSet(ids []p2p.ID) map[p2p.ID]struct{} {
	set := make(map[p2p.ID]struct{}, len(ids))
	for _, id := range ids {
		if id != "" {
			set[canonicalPeerID(id)] = struct{}{}
		}
	}
	return set
}

// canonicalPeerID folds a node ID to the form the handshake produces, so an
// ID written in config compares equal to the same ID derived from a
// connection. p2p.PubKeyToID hex-encodes, which is always lowercase, but node
// IDs are routinely copied out of tools and logs that render them uppercase.
// Without folding, such an entry passes validation and then never matches, so
// the peer it was meant to exempt is rate-shared and quota-capped like any
// other — and nothing logs the miss, making it indistinguishable from a typo.
// Applied on both sides (set construction and lookup) so the comparison stays
// case-insensitive even if either side's format changes.
func canonicalPeerID(id p2p.ID) p2p.ID {
	return p2p.ID(strings.ToLower(string(id)))
}

// ParseExemptPeerIDs splits a comma-separated node ID list from config,
// ignoring blanks so a trailing comma or an empty setting is not an error.
func ParseExemptPeerIDs(s string) []p2p.ID {
	var ids []p2p.ID
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			ids = append(ids, p2p.ID(f))
		}
	}
	return ids
}

// reserve admits n bytes for one request.
//
// The keyed layers are charged before the node-wide one and refunded if it
// then refuses. Charging global first would let a request that its own subnet
// share or quota was always going to deny still draw down the node-wide
// budget on the way to being refused — which is how requests spread thin
// across many prefixes would starve everyone else out of a ceiling that never
// actually served it anything.
func (s *servingBudget) reserve(id p2p.ID, addr string, subnet string, n float64) bool {
	keyed := !s.isExempt(id)
	if keyed && !s.subnets.reserve(subnet, n) {
		return false
	}
	if keyed && !s.quotas.reserve(addr, n) {
		s.subnets.settle(subnet, -n)
		return false
	}
	if s.global != nil && !s.global.reserve(n) {
		if keyed {
			s.subnets.settle(subnet, -n)
			s.quotas.settle(addr, -n)
		}
		return false
	}
	return true
}

// settle applies a response's real-size delta to every layer that was charged.
func (s *servingBudget) settle(id p2p.ID, addr string, subnet string, delta float64) {
	if !s.isExempt(id) {
		s.subnets.settle(subnet, delta)
		s.quotas.settle(addr, delta)
	}
	if s.global != nil {
		s.global.settle(delta)
	}
}

func (s *servingBudget) isExempt(id p2p.ID) bool {
	_, ok := s.exemptIDs[canonicalPeerID(id)]
	return ok
}

// globalAvailable reports the node-wide token count, for metrics.
func (s *servingBudget) globalAvailable() float64 {
	if s.global == nil {
		return math.Inf(1)
	}
	return s.global.available()
}

// servingReservation is the bytes one in-flight response has charged.
// respondToPeer defers release, so each of its return paths gives back
// exactly what it took without having to know which path it is on.
type servingReservation struct {
	budget *servingBudget
	id     p2p.ID
	addr   string
	subnet string
	held   float64
}

// settle replaces the admitted estimate with the response's real size,
// reporting whether the response may still be sent.
//
// An over-estimate is refunded and always succeeds. An under-estimate has to
// acquire the difference like any other admission, and can be refused: a
// budget cannot un-send bytes, so the only place a ceiling can actually be
// enforced is before the send. Charging the excess afterwards and letting the
// bucket go negative would bound nothing — responses already admitted on a
// 128 KiB estimate would all have gone out, so enough concurrent oversized
// responses could exceed the configured burst before any debt registered.
func (r *servingReservation) settle(actual float64) bool {
	if r.budget == nil {
		return true
	}
	if actual <= r.held {
		r.budget.settle(r.id, r.addr, r.subnet, actual-r.held)
		r.held = actual
		return true
	}
	if !r.budget.reserve(r.id, r.addr, r.subnet, actual-r.held) {
		return false
	}
	r.held = actual
	return true
}

// commit keeps the charge: the response has been handed to the transport.
func (r *servingReservation) commit() {
	r.held = 0
}

// release returns whatever is still held. Idempotent, and a no-op after
// commit.
func (r *servingReservation) release() {
	if r.budget == nil || r.held == 0 {
		return
	}
	r.budget.settle(r.id, r.addr, r.subnet, -r.held)
	r.held = 0
}

// sweepServingBudget retires idle keyed buckets and reports post-sweep state,
// alongside the request limiters' own sweep.
func sweepServingBudget(s *servingBudget, now time.Time, tokens, subnets, quotas metrics.Gauge) {
	s.subnets.sweep(now)
	s.quotas.sweep(now)
	tokens.Set(s.globalAvailable())
	subnets.Set(float64(s.subnets.size()))
	quotas.Set(float64(s.quotas.size()))
}

// reserveServing admits one block response against the serving budget,
// reporting whether it may be served. A persistent peer gets a reservation
// that holds nothing, so the budget never applies to it — the same exemption
// the request limiters give it.
func (bcR *Reactor) reserveServing(src p2p.Peer, exempt bool) (*servingReservation, bool) {
	if exempt {
		return &servingReservation{}, true
	}
	ip := src.RemoteIP()
	res := &servingReservation{
		budget: bcR.servingBudget,
		id:     src.ID(),
		addr:   ip.String(),
		subnet: ipRateLimitKey(ip),
		held:   estimatedResponseBytes,
	}
	if !bcR.servingBudget.reserve(res.id, res.addr, res.subnet, res.held) {
		bcR.metrics.ServingBudgetDrops.Add(1)
		return nil, false
	}
	return res, true
}

// loadExtCommit returns the extended commit to accompany a block response at
// height, or nil where vote extensions are not enabled for it. Reports false
// if a commit that should have been present is missing.
func (bcR *Reactor) loadExtCommit(height int64) (*cmtproto.ExtendedCommit, bool) {
	state, err := bcR.blockExec.Store().Load()
	if err != nil {
		bcR.Logger.Error("loading state", "err", err)
		return nil, false
	}
	if !state.ConsensusParams.ABCI.VoteExtensionsEnabled(height) {
		return nil, true
	}
	extCommit := bcR.store.LoadBlockExtendedCommit(height)
	if extCommit == nil {
		bcR.Logger.Error("found block in store with no extended commit", "height", height)
		return nil, false
	}
	return extCommit.ToProto(), true
}
