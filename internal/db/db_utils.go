package db

import (
	"encoding/hex"
	"fmt"
	"log"
	"time"
	"unicode/utf8"

	dbm "github.com/cometbft/cometbft-db"
)

func CompactSharded16(db dbm.DB, label string) error {
	startAll := time.Now()
	for b := 0x00; b <= 0xF0; b += 0x10 {
		start := []byte{byte(b)}
		var end []byte
		if b == 0xF0 {
			end = nil // nil = ∞ per prettyKey; last shard runs to end-of-keyspace
		} else {
			end = []byte{byte(b + 0x10)}
		}

		// Nice per-shard label, e.g. "kv shard 00-10" … "kv shard f0-∞"
		var shardLabel string
		if end == nil {
			shardLabel = fmt.Sprintf("%s shard %02x-∞", label, b)
		} else {
			shardLabel = fmt.Sprintf("%s shard %02x-%02x", label, b, b+0x10)
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
