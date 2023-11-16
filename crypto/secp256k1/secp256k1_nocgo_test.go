//go:build !libsecp256k1
// +build !libsecp256k1

package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenEthPrivKey(t *testing.T) {
	msg := []byte("We have lingered long enough on the shores of the cosmic ocean.")
	priv := GenPrivKey()
	t.Log("privkey ", priv)
	sigStr, err := priv.Sign(msg)
	require.NoError(t, err)
	pub := priv.PubKey()
	addr := pub.Address()
	t.Log("address ", addr)
	t.Log("pub ", pub)
	t.Log("SigStr ", sigStr)
}
