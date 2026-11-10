package blocksync

import (
	"testing"

	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"
)

func TestDeferredMessageRoundTrip(t *testing.T) {
	for _, height := range []int64{0, 9} {
		expected := &BlockDeferredResponse{Height: height}
		data, err := proto.Marshal(expected.Wrap())
		require.NoError(t, err)
		var envelope Message
		require.NoError(t, proto.Unmarshal(data, &envelope))
		actual, err := envelope.Unwrap()
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
}
