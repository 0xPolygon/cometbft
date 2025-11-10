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
