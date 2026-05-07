package db

import (
	"bytes"
	"encoding/binary"
	"testing"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/stretchr/testify/require"
)

// helper: big-endian height key with a fixed domain prefix.
func keyFn(prefix byte) KeyFunc {
	return func(h int64) []byte {
		var b [9]byte
		b[0] = prefix
		binary.BigEndian.PutUint64(b[1:], uint64(h))
		return b[:]
	}
}

func swapCompactAndLog(f func(dbm.DB, []byte, []byte, string) error) (restore func()) {
	prev := compactAndLog
	compactAndLog = f
	return func() { compactAndLog = prev }
}

// swapCompactAndMeasure intercepts the byte-measuring compaction primitive
// used by CompactSharded256 / CompactPrefixHex256 (via compactShardAdaptive).
// Returning a nonzero dWrite makes the shard count as "compacted"; returning
// 0 makes it count as "skipped_empty" from the caller's perspective.
func swapCompactAndMeasure(f func(dbm.DB, []byte, []byte, string) (uint64, error)) (restore func()) {
	prev := compactAndMeasure
	compactAndMeasure = f
	return func() { compactAndMeasure = prev }
}

func TestCompactIntSharded_DiscoveryStartsAtHugeFirstKey_NoGaps(t *testing.T) {
	var intervals [][2][]byte
	restore := swapCompactAndLog(func(db dbm.DB, start, end []byte, lbl string) error {
		intervals = append(intervals, [2][]byte{append([]byte(nil), start...), append([]byte(nil), end...)})
		// optionally call through to the real CompactAndLog if you want:
		// return CompactAndLog(db, start, end, lbl)
		return nil
	})
	defer restore()

	memdb := dbm.NewMemDB()

	// Arrange: only keys >= 25,000,000 exist; iterator should discover that as start.
	const huge = int64(25_000_000)
	kf := keyFn('h')

	// Seed a sparse-ish range starting at 'huge'
	for i := huge; i < huge+50; i++ {
		require.NoError(t, memdb.Set(kf(i), []byte{1}))
	}

	label := "blocks"

	// Sanity: no stored meta yet.
	metaKey := makeMetaKey(CompactPrefix, label)
	bz, err := memdb.Get(metaKey)
	require.NoError(t, err)
	require.Nil(t, bz)

	// Act: compact a small window to keep assertions simple.
	end := huge + 23    // exclusive
	maxSpan := int64(7) // expect: [huge,huge+7), [huge+7,huge+14), [huge+14,huge+21), [huge+21,huge+23)
	err = CompactIntSharded(memdb, huge, end, maxSpan, kf, label)
	require.NoError(t, err)

	// Assert 1: first interval starts at the HUGE discovered key.
	require.GreaterOrEqual(t, len(intervals), 1)
	require.Equal(t, 0, bytes.Compare(intervals[0][0], kf(huge)), "first shard must start at discovered huge height")

	// Assert 2: exact shard boundaries + no gaps (contiguous coverage)
	want := [][2]int64{
		{huge, huge + 7},
		{huge + 7, huge + 14},
		{huge + 14, huge + 21},
		{huge + 21, huge + 23},
	}
	require.Equal(t, len(want), len(intervals))
	for i := range want {
		startKey, endKey := intervals[i][0], intervals[i][1]
		require.Equal(t, 0, bytes.Compare(startKey, kf(want[i][0])), "shard %d start mismatch", i)
		require.Equal(t, 0, bytes.Compare(endKey, kf(want[i][1])), "shard %d end mismatch", i)
		// contiguous-coverage (no gaps):
		if i > 0 {
			require.Equal(t, 0, bytes.Compare(intervals[i-1][1], startKey), "gap between shard %d and %d", i-1, i)
		}
	}

	// Assert 3: meta persisted lastCompacted = (end-1)
	got, err := memdb.Get(metaKey)
	require.NoError(t, err)
	require.NotNil(t, got)
	last, err := decodeI64BE(got)
	require.NoError(t, err)
	require.Equal(t, end-1, last, "meta should store last compacted height")
}

func TestCompactIntSharded_ResumeFromStoredMeta_NoGaps(t *testing.T) {
	var intervals [][2][]byte
	restore := swapCompactAndLog(func(db dbm.DB, start, end []byte, lbl string) error {
		intervals = append(intervals, [2][]byte{append([]byte(nil), start...), append([]byte(nil), end...)})
		// optionally call through to the real CompactAndLog if you want:
		// return CompactAndLog(db, start, end, lbl)
		return nil
	})
	defer restore()

	memdb := dbm.NewMemDB()

	const huge = int64(25_000_000)
	kf := keyFn('h')

	// Seed from huge to huge+100 so both sessions have data
	for i := huge; i < huge+100; i++ {
		require.NoError(t, memdb.Set(kf(i), []byte{1}))
	}

	label := "blocks"
	metaKey := makeMetaKey(CompactPrefix, label)

	// Session 1
	end1 := huge + 15
	maxSpan := int64(5) // shards: [huge,huge+5), [huge+5,huge+10), [huge+10,huge+15)
	require.NoError(t, CompactIntSharded(memdb, huge, end1, maxSpan, kf, label))

	// Verify persisted last compacted = end1-1
	bz, err := memdb.Get(metaKey)
	require.NoError(t, err)
	require.NotNil(t, bz)
	last1, err := decodeI64BE(bz)
	require.NoError(t, err)
	require.Equal(t, end1-1, last1)

	// Reset captured calls for Session 2
	intervals = nil

	// Session 2 should resume at last1+1 == end1
	end2 := huge + 28
	require.NoError(t, CompactIntSharded(memdb, huge, end2, maxSpan, kf, label))

	// EXPECTED shards in session 2: [end1,end1+5), [end1+5,end1+10), [end1+10,end2)
	// i.e., [huge+15,huge+20), [huge+20,huge+25), [huge+25,huge+28)
	exp := [][2]int64{
		{end1, end1 + 5},
		{end1 + 5, end1 + 10},
		{end1 + 10, end2},
	}

	// IMPORTANT: With the current code, the resume check likely FAILS because the condition is:
	//   if bz, err := db.Get(metaKey); err != nil && bz != nil && len(bz) > 0 { ... }
	// It should be "err == nil" not "err != nil".
	//
	// Once fixed, the following assertions will pass. Until then, they may fail.
	require.Equal(t, len(exp), len(intervals), "after fix to meta read gate, resume should produce 3 shards")
	for i := range exp {
		require.Equal(t, 0, bytes.Compare(intervals[i][0], kf(exp[i][0])), "sess2 shard %d start", i)
		require.Equal(t, 0, bytes.Compare(intervals[i][1], kf(exp[i][1])), "sess2 shard %d end", i)
		if i > 0 {
			require.Equal(t, 0, bytes.Compare(intervals[i-1][1], intervals[i][0]), "gap in sess2 between shards %d and %d", i-1, i)
		}
	}

	// And meta should update to end2-1
	bz2, err := memdb.Get(metaKey)
	require.NoError(t, err)
	last2, err := decodeI64BE(bz2)
	require.NoError(t, err)
	require.Equal(t, end2-1, last2)
}

// TestCompactSharded256_SkipsEmptyShards seeds keys only under the lowercase
// 't' prefix and asserts that CompactSharded256 invokes the compactor only
// for that single shard out of 256.
func TestCompactSharded256_SkipsEmptyShards(t *testing.T) {
	var calls [][2][]byte
	restore := swapCompactAndMeasure(func(db dbm.DB, start, end []byte, lbl string) (uint64, error) {
		calls = append(calls, [2][]byte{append([]byte(nil), start...), append([]byte(nil), end...)})
		return 1, nil // nonzero so the caller counts it as "compacted"
	})
	defer restore()

	memdb := dbm.NewMemDB()
	require.NoError(t, memdb.Set([]byte("tx.height/100"), []byte{1}))
	require.NoError(t, memdb.Set([]byte("tx.hash/abcd"), []byte{1}))

	require.NoError(t, CompactSharded256(memdb, "test"))

	require.Len(t, calls, 1, "only the 't' shard (0x74) should be compacted")
	require.Equal(t, byte('t'), calls[0][0][0], "compacted shard must start at 0x74 ('t')")
}

// TestCompactSharded256_EmptyDB_NoShardsCompacted asserts that on an empty
// DB no shard is compacted at all.
func TestCompactSharded256_EmptyDB_NoShardsCompacted(t *testing.T) {
	var calls int
	restore := swapCompactAndMeasure(func(db dbm.DB, start, end []byte, lbl string) (uint64, error) {
		calls++
		return 1, nil
	})
	defer restore()

	require.NoError(t, CompactSharded256(dbm.NewMemDB(), "empty"))
	require.Zero(t, calls, "empty DB must yield zero compactions")
}

// TestCompactPrefixHex256_SkipsEmptyShards seeds two keys under "BH:" prefix
// (heights 1 and 1000) so they fall in distinct hex shards (BH:31 and BH:31
// — both '1' first byte). One shard should fire.
func TestCompactPrefixHex256_SkipsEmptyShards(t *testing.T) {
	var calls int
	restore := swapCompactAndMeasure(func(db dbm.DB, start, end []byte, lbl string) (uint64, error) {
		calls++
		return 1, nil
	})
	defer restore()

	memdb := dbm.NewMemDB()
	require.NoError(t, memdb.Set([]byte("BH:31"), []byte{1}))
	require.NoError(t, memdb.Set([]byte("BH:31000"), []byte{1}))

	require.NoError(t, CompactPrefixHex256(memdb, "BH:", "test"))

	require.Equal(t, 1, calls, "only BH:31-32 shard should fire")
}

// TestCompactShardAdaptive_NoHistory_SinglePass: with no prior dWrite stored
// the shard runs as one undivided pass.
func TestCompactShardAdaptive_NoHistory_SinglePass(t *testing.T) {
	var calls int
	restore := swapCompactAndMeasure(func(db dbm.DB, start, end []byte, lbl string) (uint64, error) {
		calls++
		return 100, nil
	})
	defer restore()

	memdb := dbm.NewMemDB()
	require.NoError(t, memdb.Set([]byte{0x42, 0x00}, []byte{1}))

	dw, err := compactShardAdaptive(memdb, []byte{0x42}, []byte{0x43}, "test", 0x42)
	require.NoError(t, err)
	require.Equal(t, uint64(100), dw)
	require.Equal(t, 1, calls, "no history -> single pass")
}

// TestCompactShardAdaptive_HotHistory_SubdividesProportionally: prior write
// of 1 GiB triggers ceil(1GiB/500MiB)=3 sub-shards; ranges interpolate over
// the parent shard.
func TestCompactShardAdaptive_HotHistory_SubdividesProportionally(t *testing.T) {
	var subs [][2][]byte
	restore := swapCompactAndMeasure(func(db dbm.DB, start, end []byte, lbl string) (uint64, error) {
		subs = append(subs, [2][]byte{append([]byte(nil), start...), append([]byte(nil), end...)})
		return 100, nil
	})
	defer restore()

	memdb := dbm.NewMemDB()
	// Seed keys spanning the entire [0x42, 0x43) range so all sub-shards are populated.
	for b := 0; b < 256; b += 16 {
		require.NoError(t, memdb.Set([]byte{0x42, byte(b)}, []byte{1}))
	}
	// Prime history: 1 GiB prior write -> ceil(1024MiB / 500MiB) = 3 sub-shards.
	writeHistoryDWrite(memdb, "test", 0x42, 1024*1024*1024)

	_, err := compactShardAdaptive(memdb, []byte{0x42}, []byte{0x43}, "test", 0x42)
	require.NoError(t, err)
	require.Equal(t, 3, len(subs), "1GiB prior should split into 3 sub-shards")

	// Verify ranges are contiguous and cover [0x42, 0x43).
	require.Equal(t, []byte{0x42}, subs[0][0])
	require.Equal(t, []byte{0x43}, subs[len(subs)-1][1])
	for i := 1; i < len(subs); i++ {
		require.Equal(t, subs[i-1][1], subs[i][0], "sub-shards must be contiguous")
	}
}

// TestSplitFactorFromHistory verifies the threshold + cap behaviour.
func TestSplitFactorFromHistory(t *testing.T) {
	const MiB = uint64(1024 * 1024)
	require.Equal(t, 1, splitFactorFromHistory(0))
	require.Equal(t, 1, splitFactorFromHistory(499*MiB))
	require.Equal(t, 1, splitFactorFromHistory(500*MiB-1))
	require.Equal(t, 1, splitFactorFromHistory(500*MiB))     // exactly threshold = single
	require.Equal(t, 2, splitFactorFromHistory(500*MiB+1))   // just above
	require.Equal(t, 3, splitFactorFromHistory(1024*MiB))    // 1 GiB -> ceil(1024/500) = 3
	require.Equal(t, 5, splitFactorFromHistory(2*1024*MiB))  // 2 GiB -> ceil(2048/500) = 5
	require.Equal(t, 8, splitFactorFromHistory(4*1024*MiB))  // 4 GiB -> 8 (just hits cap)
	require.Equal(t, 8, splitFactorFromHistory(99*1024*MiB)) // capped
}
