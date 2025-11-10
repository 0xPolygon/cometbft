package db

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"time"
	"unicode/utf8"

	dbm "github.com/cometbft/cometbft-db"
)

const (
	MaxCompactionInterval      = int64(300000)
	WaitTimeBetweenCompactions = 2 * time.Millisecond // prevents RSS/OS page cache from ballooning and smooth I/O
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
func CompactPrefixHex256(db dbm.DB, prefix string, label string) error {
	startAll := time.Now()

	if prefix == "" {
		return fmt.Errorf("prefix must be non-empty")
	}

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

		if err := compactAndLog(db, start, end, shardLabel); err != nil {
			return err
		}
	}

	log.Printf("compaction %s prefix %q ALL 256 SHARDS DONE in %s", label, prefix, time.Since(startAll))
	return nil
}

// CompactSharded256 compacts the DB into 256 ranges:
// [0x00,0x01), [0x01,0x02), …, [0xFE,0xFF), [0xFF,∞)
func CompactSharded256(db dbm.DB, label string) error {
	startAll := time.Now()

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

		if err := compactAndLog(db, start, end, shardLabel); err != nil {
			return err
		}
	}

	log.Printf("compaction %s ALL SHARDS DONE in %s", label, time.Since(startAll))
	return nil
}

// CompactAndLog compacts [start, limit) and logs the range and duration.
func CompactAndLog(db dbm.DB, start, limit []byte, label string) error {
	time.Sleep(WaitTimeBetweenCompactions)

	rng := fmt.Sprintf("[%s, %s)", prettyKey(start), prettyKey(limit))

	t0 := time.Now()
	err := db.Compact(start, limit)
	elapsed := time.Since(t0)

	if err != nil {
		log.Printf("compaction %s range %s FAILED after %s: %v", label, rng, elapsed, err)
		return err
	}
	return nil
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
		it, err := db.Iterator(start, nil)
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
