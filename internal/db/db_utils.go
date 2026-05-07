package db

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	dbm "github.com/cometbft/cometbft-db"
)

const (
	// MaxCompactionInterval caps the per-shard span fed to CompactRange.
	// A smaller value narrows the SST overlap merged in one pass at the cost
	// of more shards. 50_000 keeps each shard's working set bounded on a
	// large mainnet DB; the prior 300_000 default could merge hundreds of
	// SSTs per shard once the DB grew past steady-state.
	MaxCompactionInterval = int64(50000)

	// WaitTimeBetweenCompactions throttles successive shard compactions.
	// Linux's vm.dirty_writeback_centisecs defaults to 5s; pauses shorter
	// than that don't cross a writeback boundary so the kernel can't reliably
	// drain dirty pages between bursts. 2s gets us past the writeback flush
	// without idling forever and is the dominant lever for keeping page
	// cache from accumulating across shards.
	WaitTimeBetweenCompactions = 2 * time.Second

	// SubshardSplitThresholdBytes is the per-shard write-byte threshold above
	// which the next prune cycle subdivides that shard. We cap subshard count
	// at SubshardMaxSplit so a 4 GB shard becomes 8 sub-shards of ~500 MB,
	// not 80 sub-shards. Below this threshold a shard runs un-split.
	SubshardSplitThresholdBytes = uint64(500 * 1024 * 1024) // 500 MiB
	SubshardMaxSplit            = 8

	// CompactHistoryPrefix scopes adaptive-sharding metadata (per-shard prior
	// dWrite). Stored alongside CompactPrefix in the same DB so resume +
	// adaptive-split state share a key namespace.
	compactHistoryPrefix = "compact_history_"
)

var (
	CompactPrefix = []byte("compact_")
	compactAndLog = CompactAndLog
)

// KeyFunc maps an integer (e.g., block height) to a DB key.
// It MUST be strictly increasing with respect to lexicographic order:
//
//	keyFn(h+1) > keyFn(h)   for all h.
type KeyFunc func(int64) []byte

// encodeI64BE / decodeI64BE store the last compacted height in 8 bytes (big-endian).
func encodeI64BE(v int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	return b[:]
}
func decodeI64BE(bz []byte) (int64, error) {
	if len(bz) != 8 {
		return 0, fmt.Errorf("invalid stored height bytes (len=%d)", len(bz))
	}
	return int64(binary.BigEndian.Uint64(bz)), nil
}

// makeMetaKey = metaPrefix || label
func makeMetaKey(metaPrefix []byte, label string) []byte {
	k := make([]byte, 0, len(metaPrefix)+len(label))
	k = append(k, metaPrefix...)
	k = append(k, []byte(label)...) // label scoping
	return k
}

// CompactIntSharded compacts the integer interval [start, end) in shards of size <= maxSpan,
// but the starting height is read from (and then persisted to) the DB.
// Params details:
//   - The initialHeigh is the one set on genesis, available on stateStore
//
// Persistence details:
//   - Uses metaPrefix+label as a key to store the *last compacted height* (int64 BE).
//   - If none stored, discovers the start height by:
//     (1) iterating from keyFn(0) to the first present key,
//     (2) verifying the key is within [keyFn(0), keyFn(maxInt64)),
//     (3) binary-searching for the smallest h with keyFn(h) >= firstKey (monotone property),
//     and using that h as the starting height.
//
// After each shard compaction, it stores lastCompactedHeight = e-1, so a restart can resume from (last+1).
func CompactIntSharded(
	db dbm.DB,
	initialHeight int64,
	end, maxSpan int64,
	keyFn KeyFunc,
	label string,
) error {
	if keyFn == nil {
		return fmt.Errorf("keyFn must not be nil")
	}
	if maxSpan <= 0 {
		return fmt.Errorf("maxSpan must be > 0")
	}
	if end <= 0 {
		// nothing to compact
		return nil
	}

	// --- determine starting height from DB (or discover if not present) ---
	metaKey := makeMetaKey(CompactPrefix, label)
	var start int64

	if bz, err := db.Get(metaKey); err == nil && bz != nil && len(bz) > 0 {
		last, err := decodeI64BE(bz)
		if err != nil {
			return fmt.Errorf("failed to decode last compacted height: %w", err)
		}
		start = last + 1 // resume *after* last compacted
	} else {
		start = initialHeight
	}

	// Guard against overshoot or empty work.
	if start >= end {
		return nil
	}

	allStart := time.Now()
	for s := start; s < end; s += maxSpan {
		e := s + maxSpan
		if e > end {
			e = end
		}

		shardLabel := fmt.Sprintf("%s [%d,%d)", label, s, e)
		if err := compactAndLog(db, keyFn(s), keyFn(e), shardLabel); err != nil {
			return err
		}

		// Persist last compacted height = e-1 so we can resume at (e-1)+1 = e.
		lastCompacted := e - 1
		if err := db.Set(metaKey, encodeI64BE(lastCompacted)); err != nil {
			return fmt.Errorf("failed to store last compacted height: %w", err)
		}
	}

	log.Printf("compaction %s ALL SHARDS DONE in %s (range [%d,%d), maxSpan=%d)",
		label, time.Since(allStart), start, end, maxSpan)
	return nil
}

// CompactPrefixHex256 shards a given ASCII prefix into 256 ranges based on the
// first *byte* of the hex-encoded suffix (two hex chars), then compacts each shard.
//
// For prefix "BH:", shards are lexicographic ranges:
// ["BH:00","BH:01"), ["BH:01","BH:02"), …, ["BH:fe","BH:ff"), ["BH:ff","BH:fg")
//
// The final shard ends at "BH:fg" so that every key starting with "BH:ff"
// compares < "BH:fg" (since 'g' is the next ASCII char after 'f').
//
// Shards that contain no keys are detected by a one-row Iterator probe and
// skipped — on real workloads this prunes ~220 of 256 shards because key
// schemas concentrate in the lowercase-ASCII zone.
func CompactPrefixHex256(db dbm.DB, prefix string, label string) error {
	startAll := time.Now()

	if prefix == "" {
		return fmt.Errorf("prefix must be non-empty")
	}

	var compacted, skipped int
	for b := 0; b <= 0xFF; b++ {
		start := []byte(fmt.Sprintf("%s%02x", prefix, b))

		var end []byte
		if b < 0xFF {
			end = []byte(fmt.Sprintf("%s%02x", prefix, b+1))
		} else {
			// End sentinel for the last shard: bump 'f' -> 'g'
			// to cap everything that starts with "...ff"
			end = append([]byte(prefix), 'f', 'g')
		}

		// Nice label, e.g. `prune BH: 00-01`, ..., `prune BH: ff-g`
		var shardLabel string
		if b < 0xFF {
			shardLabel = fmt.Sprintf("%s %s %02x-%02x", label, prefix, b, b+1)
		} else {
			shardLabel = fmt.Sprintf("%s %s ff-fg", label, prefix)
		}

		dw, err := compactShardAdaptive(db, start, end, label, b)
		if err != nil {
			return fmt.Errorf("compaction %s: %w", shardLabel, err)
		}
		if dw == 0 {
			skipped++
			continue
		}
		compacted++
	}

	log.Printf("compaction %s prefix %q DONE in %s (compacted=%d skipped_empty=%d)",
		label, prefix, time.Since(startAll), compacted, skipped)
	return nil
}

// CompactSharded256 compacts the DB into 256 ranges:
// [0x00,0x01), [0x01,0x02), …, [0xFE,0xFF), [0xFF,∞)
//
// Shards that contain no keys are detected by a one-row Iterator probe and
// skipped. CometBFT key schemas (e.g. "tx.hash", "block.height", event-type
// prefixes) concentrate keys in the lowercase-ASCII zone, leaving ~220 of
// the 256 shards empty on real workloads.
func CompactSharded256(db dbm.DB, label string) error {
	startAll := time.Now()

	var compacted, skipped int
	for b := 0; b < 256; b++ {
		start := []byte{byte(b)}
		var end []byte
		if b < 255 {
			end = []byte{byte(b + 1)}
		} else {
			end = nil // nil = ∞ (end-of-keyspace)
		}

		var shardLabel string
		if end == nil {
			shardLabel = fmt.Sprintf("%s shard %02x-∞", label, b)
		} else {
			shardLabel = fmt.Sprintf("%s shard %02x-%02x", label, b, b+1)
		}

		dw, err := compactShardAdaptive(db, start, end, label, b)
		if err != nil {
			return fmt.Errorf("compaction %s: %w", shardLabel, err)
		}
		if dw == 0 {
			skipped++
			continue
		}
		compacted++
	}

	log.Printf("compaction %s DONE in %s (compacted=%d skipped_empty=%d)",
		label, time.Since(startAll), compacted, skipped)
	return nil
}

// shardHasKeys reports whether any key exists in [start, end). Cost is one
// SeekGE — microseconds — versus a full CompactRange which on a populated DB
// rewrites overlapping SSTs. Uses DontFillCache so the probe doesn't pollute
// goleveldb's block cache.
func shardHasKeys(db dbm.DB, start, end []byte) (bool, error) {
	it, err := dbm.IteratorWithOpts(db, start, end, &dbm.ReadOptions{DontFillCache: true})
	if err != nil {
		return false, err
	}
	defer it.Close()
	return it.Valid(), nil
}

// historyKey returns the metadata key under which we persist the prior-cycle
// dWrite for a (label, shardIdx) pair. The shard index is the byte b in
// CompactSharded256 / CompactPrefixHex256.
func historyKey(label string, shardIdx int) []byte {
	return []byte(fmt.Sprintf("%s%s_%03d", compactHistoryPrefix, label, shardIdx))
}

func readHistoryDWrite(db dbm.DB, label string, shardIdx int) uint64 {
	bz, err := db.Get(historyKey(label, shardIdx))
	if err != nil || len(bz) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(bz)
}

func writeHistoryDWrite(db dbm.DB, label string, shardIdx int, dWrite uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], dWrite)
	_ = db.Set(historyKey(label, shardIdx), b[:])
}

// splitFactorFromHistory maps prior-cycle dWrite to a sub-shard count.
// Below threshold: 1 (no split). Above: ceil(prior / threshold), capped.
func splitFactorFromHistory(priorDWrite uint64) int {
	if priorDWrite < SubshardSplitThresholdBytes {
		return 1
	}
	n := int((priorDWrite + SubshardSplitThresholdBytes - 1) / SubshardSplitThresholdBytes)
	if n > SubshardMaxSplit {
		n = SubshardMaxSplit
	}
	if n < 1 {
		n = 1
	}
	return n
}

// byteRangeSplit divides [start, end) into n sub-ranges by interpolating an
// extra byte after `start`. The returned ranges are contiguous and cover
// exactly [start, end). For the open-ended case end==nil it splits the
// keyspace [start, ∞) using ascending second-byte interpolation; the final
// sub-range stays open-ended.
//
// Examples (n=4):
//
//	[0x00, 0x01) -> [0x00, 0x0040), [0x0040, 0x0080), [0x0080, 0x00c0), [0x00c0, 0x01)
//	[0x42, 0x43) -> [0x42, 0x4240), ..., [0x42c0, 0x43)
func byteRangeSplit(start, end []byte, n int) [][2][]byte {
	if n <= 1 {
		return [][2][]byte{{start, end}}
	}
	out := make([][2][]byte, 0, n)
	for i := 0; i < n; i++ {
		var sStart, sEnd []byte
		if i == 0 {
			sStart = start
		} else {
			sStart = appendInterpolant(start, i, n)
		}
		if i == n-1 {
			sEnd = end
		} else {
			sEnd = appendInterpolant(start, i+1, n)
		}
		out = append(out, [2][]byte{sStart, sEnd})
	}
	return out
}

// appendInterpolant returns start || byte(i*256/n). Used to interpolate
// sub-shard boundaries inside a single-byte shard range.
func appendInterpolant(start []byte, i, n int) []byte {
	b := byte((i * 256) / n)
	out := make([]byte, len(start)+1)
	copy(out, start)
	out[len(start)] = b
	return out
}

// compactShardAdaptive runs a single shard, optionally subdividing based on
// the prior-cycle write history persisted in the DB. Returns the cumulative
// dWrite observed for this shard (which becomes the next cycle's history).
//
// The skip-empty probe runs at the *sub*-shard level too: a shard whose
// data clusters in part of its range will only re-compact the populated
// sub-ranges next cycle.
func compactShardAdaptive(db dbm.DB, start, end []byte, label string, shardIdx int) (uint64, error) {
	prior := readHistoryDWrite(db, label, shardIdx)
	splitN := splitFactorFromHistory(prior)
	subs := byteRangeSplit(start, end, splitN)

	var totalDW uint64
	for i, sub := range subs {
		var subLabel string
		if splitN == 1 {
			subLabel = fmt.Sprintf("%s shard %02x", label, shardIdx)
		} else {
			subLabel = fmt.Sprintf("%s shard %02x sub %d/%d", label, shardIdx, i+1, splitN)
		}
		hasAny, err := shardHasKeys(db, sub[0], sub[1])
		if err != nil {
			return totalDW, fmt.Errorf("%s probe failed: %w", subLabel, err)
		}
		if !hasAny {
			continue
		}
		dw, err := compactAndMeasure(db, sub[0], sub[1], subLabel)
		if err != nil {
			return totalDW, err
		}
		totalDW += dw
	}
	if totalDW > 0 {
		// Only persist when we actually wrote something. Writing zeros for
		// every empty shard would pollute the keyspace with metadata keys
		// inside the same byte-shard ranges we're sweeping (history keys
		// start with 'c' = 0x63, which would otherwise fall into shard 0x63
		// on the next sweep and force a spurious compaction).
		writeHistoryDWrite(db, label, shardIdx, totalDW)
	}
	return totalDW, nil
}

// CompactAndLog compacts [start, limit) and logs the range, duration, and
// the process-level read/write byte deltas observed during the call. The
// byte deltas come from /proc/self/io and capture *all* I/O issued by the
// process during the compact (including background goroutines), so they're
// upper bounds — but they pin per-shard amplification cost in production.
func CompactAndLog(db dbm.DB, start, limit []byte, label string) error {
	_, err := compactAndMeasure(db, start, limit, label)
	return err
}

// compactAndMeasure is the shared implementation for both the dWrite-returning
// adaptive path and the legacy CompactAndLog signature. Returns the observed
// /proc/self/io write_bytes delta so callers can persist it for adaptive
// sub-sharding decisions on the next cycle.
var compactAndMeasure = realCompactAndMeasure

func realCompactAndMeasure(db dbm.DB, start, limit []byte, label string) (uint64, error) {
	time.Sleep(WaitTimeBetweenCompactions)

	rng := fmt.Sprintf("[%s, %s)", prettyKey(start), prettyKey(limit))

	rb0, wb0 := procIOBytes()
	t0 := time.Now()
	err := db.Compact(start, limit)
	elapsed := time.Since(t0)
	rb1, wb1 := procIOBytes()

	if err != nil {
		log.Printf("compaction %s range %s FAILED after %s: %v", label, rng, elapsed, err)
		return 0, err
	}
	dWrite := wb1 - wb0
	log.Printf("compaction %s range %s done in %s dRead=%dB dWrite=%dB",
		label, rng, elapsed, rb1-rb0, dWrite)
	return dWrite, nil
}

// procIOBytes reads /proc/self/io and returns (read_bytes, write_bytes).
// On non-linux or read failure, returns (0, 0); the resulting delta of 0
// is logged unobtrusively rather than failing the compaction.
func procIOBytes() (uint64, uint64) {
	f, err := os.Open("/proc/self/io")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	var rb, wb uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "read_bytes:"):
			v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "read_bytes:")), 10, 64)
			if err == nil {
				rb = v
			}
		case strings.HasPrefix(line, "write_bytes:"):
			v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "write_bytes:")), 10, 64)
			if err == nil {
				wb = v
			}
		}
	}
	return rb, wb
}

// prettyKey renders a key as quoted ASCII if possible, otherwise as hex.
// nil renders as ∞ (end-of-keyspace).
func prettyKey(b []byte) string {
	if b == nil {
		return "∞"
	}
	if isASCIIPrintable(b) && utf8.Valid(b) {
		// %q to make delimiters/whitespace visible and safe
		return fmt.Sprintf("%q", string(b))
	}
	return "0x" + hex.EncodeToString(b)
}

func isASCIIPrintable(b []byte) bool {
	for _, c := range b {
		// allow common printable ASCII including space; exclude DEL
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// findSmallestValueWithBrokenKeys attempts to find the smallest numeric value
// among keys that share a given prefix.
//
// Note: The key format is **not properly designed** — numeric values are
// concatenated as plain strings (e.g. "SC:2", "SC:10"), which causes lexicographic
// rather than numeric ordering. This function compensates for that by iterating
// through possible first digits and parsing keys manually.
//
// Example key set: "SC:2", "SC:10", "SC:3" → returns 2
//
// This is a workaround and should be replaced when the key schema is improved.
func FindSmallestValueWithBrokenKeys(db dbm.DB, prefix []byte) (int, error) {
	var smallest *int

	// We assume numeric suffixes can start with digits 0–9
	for d := byte('0'); d <= byte('9'); d++ {
		start := append(append([]byte{}, prefix...), d)
		// Called on every ABCI-results pruning cycle. Skip the goleveldb
		// block cache so these scans don't pollute it.
		it, err := dbm.IteratorWithOpts(db, start, nil, &dbm.ReadOptions{DontFillCache: true})
		if err != nil {
			return 0, fmt.Errorf("failed to iterate prefix %q: %w", start, err)
		}

		for ; it.Valid(); it.Next() {
			key := it.Key()
			if !bytes.HasPrefix(key, prefix) {
				break // passed beyond the prefix
			}

			// Extract numeric part after prefix
			suffix := bytes.TrimPrefix(key, prefix)
			if len(suffix) == 0 {
				continue
			}

			n, err := strconv.Atoi(string(suffix))
			if err != nil {
				// Skip non-numeric keys gracefully
				continue
			}

			if smallest == nil || n < *smallest {
				smallest = &n
			}
		}

		it.Close()
	}

	if smallest == nil {
		return 0, fmt.Errorf("no valid numeric keys found for prefix %q", prefix)
	}

	return *smallest, nil
}
