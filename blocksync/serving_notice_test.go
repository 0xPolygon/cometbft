package blocksync

import (
	"testing"
	"time"

	"github.com/cometbft/cometbft/p2p"
	bc "github.com/cometbft/cometbft/proto/tendermint/blocksync"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"
)

type deferredNoticePeer struct {
	*blockServingPeer
	notices chan int64
}

func (p *deferredNoticePeer) TrySend(e p2p.Envelope) bool {
	if response, ok := e.Message.(*bc.BlockDeferredResponse); ok {
		p.notices <- response.Height
	}
	return true
}

func TestDeferredNoticeNegotiation(t *testing.T) {
	for _, accept := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "supported"}[accept], func(t *testing.T) {
			policy := &deferredTestPolicy{}
			d := newDeferredBlocks(&Reactor{}, policy)
			t.Cleanup(d.stop)
			peer := &deferredNoticePeer{blockServingPeer: newBlockServingPeer(t, false), notices: make(chan int64, 10)}
			require.True(t, d.enqueue(peer, 1, accept))
			require.Eventually(t, func() bool { return policy.retries.Load() >= 2 }, time.Second, time.Millisecond)
			d.stop()
			if accept {
				require.Len(t, peer.notices, 1)
				require.Equal(t, int64(1), <-peer.notices)
			} else {
				require.Empty(t, peer.notices)
			}
		})
	}
}

func TestDeferredNoticeWire(t *testing.T) {
	request := new(bc.BlockRequest)
	require.NoError(t, proto.Unmarshal([]byte{8, 1}, request))
	require.False(t, request.AcceptDeferred)
	encoded, err := proto.Marshal((&bc.BlockDeferredResponse{Height: 4}).Wrap())
	require.NoError(t, err)
	var envelope bc.Message
	require.NoError(t, proto.Unmarshal(encoded, &envelope))
	unwrapped, err := envelope.Unwrap()
	require.NoError(t, err)
	require.Equal(t, &bc.BlockDeferredResponse{Height: 4}, unwrapped)
	require.NoError(t, ValidateMsg(unwrapped))
	require.NoError(t, ValidateMsg(&bc.BlockDeferredResponse{Height: 0}))
	require.Error(t, ValidateMsg(&bc.BlockDeferredResponse{Height: -1}))
}
