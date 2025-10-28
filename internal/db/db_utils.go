package db

import (
	"encoding/hex"
	"fmt"
	"log"
	"time"
	"unicode/utf8"

	dbm "github.com/cometbft/cometbft-db"
)

// CompactPrefixSharded16 shards a given ASCII prefix into 16 ranges by the
// first byte *after* the prefix, then compacts each shard.
// For prefix "BH:", shards are:
// ["BH:\x00","BH:\x10"), ["BH:\x10","BH:\x20"), …, ["BH:\xF0","BH;")
func CompactPrefixSharded16(db dbm.DB, prefix string, label string) error {
	startAll := time.Now()
	p := []byte(prefix)
	if len(p) == 0 {
		return fmt.Errorf("prefix must be non-empty")
	}

	for b := 0x00; b <= 0xF0; b += 0x10 {
		start := append(append([]byte{}, p...), byte(b))

		var end []byte
		if b == 0xF0 {
			// end of the prefix space: increment ':' (0x3A) to ';' (0x3B)
			// so every key with "BH:" prefix compares < "BH;"
			end = []byte(prefix)
			end[len(end)-1]++ // ':' -> ';'
		} else {
			end = append(append([]byte{}, p...), byte(b+0x10))
		}

		// Nice label: e.g. `prune BH: 00-10`, ..., `prune BH: f0-;`
		var shardLabel string
		if b == 0xF0 {
			shardLabel = fmt.Sprintf("%s %s %02x-;", label, prefix, b)
		} else {
			shardLabel = fmt.Sprintf("%s %s %02x-%02x", label, prefix, b, b+0x10)
		}

		if err := CompactAndLog(db, start, end, shardLabel); err != nil {
			return err
		}
	}

	log.Printf("compaction %s prefix %q ALL SHARDS DONE in %s", label, prefix, time.Since(startAll))
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
