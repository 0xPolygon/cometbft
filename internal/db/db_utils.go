package db

import (
	"encoding/hex"
	"fmt"
	"log"
	"time"
	"unicode/utf8"

	dbm "github.com/cometbft/cometbft-db"
)

const (
	MaxCompactionInterval      = 100000
	WaitTimeBetweenCompactions = 2 * time.Millisecond // prevents RSS/OS page cache from ballooning and smooth I/O
)

// KeyFunc maps an integer (e.g., block height) to a DB key.
type KeyFunc func(int64) []byte

// CompactIntSharded compacts the integer interval [start, end) in shards of size <= maxSpan,
// calling CompactAndLog for each shard using keyFn to map integers to keys.
func CompactIntSharded(db dbm.DB, start, end, maxSpan int64, keyFn KeyFunc, label string) error {
	if keyFn == nil {
		return fmt.Errorf("keyFn must not be nil")
	}
	if maxSpan <= 0 {
		return fmt.Errorf("maxSpan must be > 0")
	}
	if start >= end {
		// nothing to compact
		return nil
	}

	allStart := time.Now()
	for s := start; s < end; s += maxSpan {
		e := s + maxSpan
		if e > end {
			e = end
		}

		shardLabel := fmt.Sprintf("%s [%d,%d)", label, s, e)
		if err := CompactAndLog(db, keyFn(s), keyFn(e), shardLabel); err != nil {
			return err
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

		if err := CompactAndLog(db, start, end, shardLabel); err != nil {
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

		if err := CompactAndLog(db, start, end, shardLabel); err != nil {
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
	log.Printf("compacting %s range %s ...", label, rng)

	t0 := time.Now()
	err := db.Compact(start, limit)
	elapsed := time.Since(t0)

	if err != nil {
		log.Printf("compaction %s FAILED after %s: %v", label, elapsed, err)
		return err
	}
	log.Printf("compaction %s DONE in %s", label, elapsed)
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
