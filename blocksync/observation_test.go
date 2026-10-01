package blocksync

import (
	"testing"

	cmtcfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/mocks"
	"github.com/cometbft/cometbft/p2p/observation"
	bc "github.com/cometbft/cometbft/proto/tendermint/blocksync"
	ct "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"
)

type validationObserver struct {
	ids    []string
	events []observation.Event
}

func (o *validationObserver) Observe(id string, e observation.Event) {
	o.ids = append(o.ids, id)
	o.events = append(o.events, e)
}

func TestPeerObservationBlockValidation(t *testing.T) {
	block := types.MakeBlock(1, nil, &types.Commit{}, nil)
	block.ValidatorsHash = []byte("12345678901234567890123456789012")
	// BlockFromProto permits an empty last commit only at height 1.
	block.ProposerAddress = make([]byte, 20)
	pb, err := block.ToProto()
	require.NoError(t, err)
	_, err = types.BlockFromProto(pb)
	require.NoError(t, err)
	for _, msg := range []proto.Message{
		&bc.BlockRequest{Height: -1},
		&bc.BlockResponse{},
		&bc.BlockResponse{Block: pb, ExtCommit: &ct.ExtendedCommit{Height: -1}},
	} {
		o := &validationObserver{}
		cfg := cmtcfg.DefaultP2PConfig()
		cfg.PeerObserver = o
		r := &Reactor{}
		r.BaseReactor = *p2p.NewBaseReactor("test", r)
		r.SetSwitch(p2p.NewSwitch(cfg, nil))
		peer := &mocks.Peer{}
		peer.On("ID").Return(p2p.ID("peer"))
		peer.On("IsRunning").Return(false)
		r.Receive(p2p.Envelope{Src: peer, ChannelID: BlocksyncChannel, Message: msg})
		require.Equal(t, []string{"peer"}, o.ids)
		require.Equal(t, []observation.Event{{Kind: observation.InvalidMessage, Channel: BlocksyncChannel}}, o.events)
		peer.AssertCalled(t, "IsRunning") // existing disconnect path still executes
	}
}
