package conn

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMConnectionSendQueueFull(t *testing.T) {
	for _, capacity := range []int{1, 1000} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			mconn := NewMConnection(nil, []*ChannelDescriptor{
				{ID: 0x40, Priority: 1, SendQueueCapacity: capacity},
				{ID: 0x20, Priority: 1},
			}, nil, nil)
			channel := mconn.channelsIdx[0x40]
			require.False(t, mconn.SendQueueFull(0x40))
			for size := 1; size <= capacity; size++ {
				require.True(t, channel.trySendBytes([]byte{1}))
				require.Equal(t, size == capacity, mconn.SendQueueFull(0x40), "size %d", size)
			}
			require.False(t, mconn.SendQueueFull(0x20))
			require.False(t, mconn.SendQueueFull(0xff))
			require.True(t, channel.isSendPending())
			require.True(t, mconn.SendQueueFull(0x40))
			require.True(t, channel.trySendBytes([]byte{1}))
			require.Equal(t, capacity+1, channel.loadSendQueueSize())
			require.True(t, mconn.SendQueueFull(0x40))
			channel.nextPacketMsg()
			require.True(t, mconn.SendQueueFull(0x40))
			require.True(t, channel.isSendPending())
			channel.nextPacketMsg()
			require.False(t, mconn.SendQueueFull(0x40))
			for channel.isSendPending() {
				channel.nextPacketMsg()
			}
			require.Zero(t, channel.loadSendQueueSize())
			var full bool
			require.Zero(t, testing.AllocsPerRun(100, func() { full = mconn.SendQueueFull(0x40) }))
			require.False(t, full)
		})
	}
}

func BenchmarkMConnectionSendQueueFull(b *testing.B) {
	descriptors := make([]*ChannelDescriptor, 10)
	for i := range descriptors {
		descriptors[i] = &ChannelDescriptor{ID: byte(i), Priority: 1, SendQueueCapacity: 1000}
	}
	mconn := NewMConnection(nil, descriptors, nil, nil)
	for i := 0; i < 1000; i++ {
		mconn.channelsIdx[5].trySendBytes([]byte{1})
	}
	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		var full bool
		for i := 0; i < b.N; i++ {
			full = mconn.SendQueueFull(5)
		}
		require.True(b, full)
	})
	b.Run("status", func(b *testing.B) {
		b.ReportAllocs()
		var full bool
		for i := 0; i < b.N; i++ {
			for _, channel := range mconn.Status().Channels {
				if channel.ID == 5 {
					full = channel.SendQueueCapacity > 0 && channel.SendQueueSize >= channel.SendQueueCapacity
					break
				}
			}
		}
		require.True(b, full)
	})
}
