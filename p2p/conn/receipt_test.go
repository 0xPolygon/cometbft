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
