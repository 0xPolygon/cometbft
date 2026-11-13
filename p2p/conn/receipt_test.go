package conn

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTrackedSendCompletion(t *testing.T) {
	for _, flushed := range []bool{false, true} {
		t.Run(map[bool]string{true: "flush", false: "stop"}[flushed], func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			c := NewMConnectionWithConfig(a, []*ChannelDescriptor{{ID: 1, Priority: 1, SendQueueCapacity: 4}}, func(byte, []byte) {}, func(interface{}) {}, DefaultMConnConfig())
			c.config.FlushThrottle = time.Hour
			require.NoError(t, c.Start())
			completed := make(chan bool, 2)
			require.True(t, c.TrySendTracked(1, []byte("native payload"), func(ok bool) { completed <- ok }))
			require.Eventually(t, func() bool {
				c.receiptMu.Lock()
				defer c.receiptMu.Unlock()
				for r := range c.receipts {
					if r.written {
						return true
					}
				}
				return false
			}, time.Second, time.Millisecond)
			select {
			case <-completed:
				t.Fatal("queueing is not a completed flush")
			default:
			}
			if flushed {
				go func() { _, _ = io.Copy(io.Discard, b) }()
				c.FlushStop()
			} else {
				require.NoError(t, c.Stop())
			}
			select {
			case result := <-completed:
				require.Equal(t, flushed, result)
			case <-time.After(time.Second):
				t.Fatal("missing completion")
			}
			c.cancelReceipts()
			select {
			case <-completed:
				t.Fatal("duplicate completion")
			default:
			}
			require.False(t, c.TrySendTracked(1, []byte{1}, func(bool) { t.Error("callback on rejected send") }))
		})
	}
}

func TestTrackedConcurrentShutdown(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := NewMConnection(a, []*ChannelDescriptor{{ID: 1, Priority: 1, SendQueueCapacity: 4}}, func(byte, []byte) {}, func(interface{}) {})
	c.config.FlushThrottle = time.Hour
	require.NoError(t, c.Start())
	var queued, finished atomic.Int64
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.TrySendTracked(1, make([]byte, 2000), func(bool) { finished.Add(1) }) {
				queued.Add(1)
			}
		}()
	}
	require.NoError(t, c.Stop())
	wg.Wait()
	require.Equal(t, queued.Load(), finished.Load())
}

func TestTrackedFlushFailureKeepsQueuedReservations(t *testing.T) {
	c := &MConnection{receipts: make(map[*sendReceipt]struct{})}
	var completed []bool
	written := &sendReceipt{written: true, callback: func(ok bool) { completed = append(completed, ok) }}
	queued := &sendReceipt{callback: func(ok bool) { completed = append(completed, ok) }}
	c.receipts[written] = struct{}{}
	c.receipts[queued] = struct{}{}
	c.finishFlushed(false)
	require.Equal(t, []bool{false}, completed)
	require.Contains(t, c.receipts, queued)
	c.cancelReceipts()
	require.Equal(t, []bool{false, false}, completed)
	require.Empty(t, c.receipts)
	c.cancelReceipts()
	require.Len(t, completed, 2)
}

func TestTrackedRejectsUnknownChannel(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	c := NewMConnection(a, []*ChannelDescriptor{{ID: 1, Priority: 1}}, func(byte, []byte) {}, func(interface{}) {})
	require.NoError(t, c.Start())
	t.Cleanup(func() { require.NoError(t, c.Stop()) })
	var callbacks atomic.Int64
	require.False(t, c.TrySendTracked(2, []byte("unknown channel"), func(bool) { callbacks.Add(1) }))
	// A rejected message leaves ownership with the caller. It must neither
	// acquire a receipt nor leave the receipt lock held for a subsequent send.
	c.receiptMu.Lock()
	require.Empty(t, c.receipts)
	c.receiptMu.Unlock()
	require.True(t, c.TrySendTracked(1, []byte("known channel"), func(bool) { callbacks.Add(1) }))
	c.cancelReceipts()
	require.Equal(t, int64(1), callbacks.Load())
}

type trackedBlockedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *trackedBlockedConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestTrackedQueueFullRetainsCallerOwnership(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	blocked := &trackedBlockedConn{Conn: a, started: make(chan struct{})}
	c := NewMConnection(blocked, []*ChannelDescriptor{{ID: 1, Priority: 1, SendQueueCapacity: 1}}, func(byte, []byte) {}, func(interface{}) {})
	require.NoError(t, c.Start())
	t.Cleanup(func() { require.NoError(t, c.Stop()) })
	var completed atomic.Int64
	done := func(ok bool) { require.False(t, ok); completed.Add(1) }
	require.True(t, c.TrySendTracked(1, make([]byte, 64<<10), done))
	// The socket is now blocked with the first frame. Fill the sole remaining
	// queue slot so refusal is deterministic regardless of writer scheduling.
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("writer did not reach the socket")
	}
	require.True(t, c.TrySendTracked(1, []byte{1}, done))
	require.False(t, c.TrySendTracked(1, []byte{2}, done))
	c.receiptMu.Lock()
	require.Len(t, c.receipts, 2)
	c.receiptMu.Unlock()
	c.cancelReceipts()
	require.Equal(t, int64(2), completed.Load())
}
