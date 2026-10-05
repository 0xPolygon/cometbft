package p2p

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p/conn"
	"github.com/cometbft/cometbft/p2p/observation"
	pp "github.com/cometbft/cometbft/proto/tendermint/p2p"
	"github.com/stretchr/testify/require"
)

type connectionPolicy struct {
	denied  atomic.Bool
	calls   atomic.Int64
	trigger observation.Kind
	observe bool
}

func (p *connectionPolicy) AllowPeer(string) bool {
	p.calls.Add(1)
	return !p.denied.Load()
}

func (p *connectionPolicy) Observe(_ string, event observation.Event) {
	if p.observe && event.Kind == p.trigger {
		p.denied.Store(true)
	}
}

func TestConnectionPolicyAdmission(t *testing.T) {
	for _, outbound := range []bool{false, true} {
		t.Run(map[bool]string{false: "inbound", true: "outbound"}[outbound], func(t *testing.T) {
			policy := &connectionPolicy{}
			policy.denied.Store(true)
			local := observedSwitch(t, nil, policy)
			remote := observedSwitch(t, nil)
			if outbound {
				err := local.DialPeerWithAddress(remote.NetAddress())
				require.ErrorContains(t, err, "connection rejected by peer policy")
				var rejected ErrRejected
				require.ErrorAs(t, err, &rejected)
				require.True(t, rejected.IsFiltered())
				require.False(t, isTerminalDialErr(err))
			} else {
				require.NoError(t, remote.DialPeerWithAddress(local.NetAddress()))
			}
			require.Eventually(t, func() bool { return policy.calls.Load() > 0 && local.Peers().Size() == 0 && remote.Peers().Size() == 0 }, time.Second, 10*time.Millisecond)
			// Expiry in the application ledger reopens admission without a second timer.
			policy.denied.Store(false)
			require.NoError(t, remote.DialPeerWithAddress(local.NetAddress()))
			require.Eventually(t, func() bool { return local.Peers().Size() == 1 }, time.Second, 10*time.Millisecond)
		})
	}
}

func TestConnectionPolicyActivity(t *testing.T) {
	for _, kind := range []observation.Kind{observation.Received, observation.Queued} {
		t.Run(map[observation.Kind]string{observation.Received: "received", observation.Queued: "queued"}[kind], func(t *testing.T) {
			policy := &connectionPolicy{observe: true, trigger: kind}
			receiver := observedSwitch(t, policy, policy)
			sender := observedSwitch(t, nil)
			require.NoError(t, sender.DialPeerWithAddress(receiver.NetAddress()))
			require.Eventually(t, func() bool { return receiver.Peers().Size() == 1 }, time.Second, 10*time.Millisecond)
			sending, target := sender, receiver
			if kind == observation.Queued {
				sending, target = receiver, sender
			}
			peer := sending.Peers().Get(target.NodeInfo().ID())
			require.True(t, peer.Send(Envelope{ChannelID: testCh, Message: &pp.PexRequest{}}))
			require.Eventually(t, func() bool { return receiver.Peers().Size() == 0 && sender.Peers().Size() == 0 }, time.Second, 10*time.Millisecond)
			require.True(t, policy.denied.Load())
			if kind == observation.Received {
				require.Empty(t, receiver.Reactor("foo").(*TestReactor).getMsgs(testCh))
			}
			require.NoError(t, sender.DialPeerWithAddress(receiver.NetAddress()))
			require.Eventually(t, func() bool { return sender.Peers().Size() == 0 }, time.Second, 10*time.Millisecond)
			require.Zero(t, receiver.Peers().Size())
		})
	}
}

func TestConnectionPolicySendAdmission(t *testing.T) {
	policy := &connectionPolicy{}
	local := observedSwitch(t, nil, policy)
	remote := observedSwitch(t, nil)
	require.NoError(t, local.AddPersistentPeers([]string{remote.NetAddress().String()}))
	require.NoError(t, local.DialPeerWithAddress(remote.NetAddress()))
	p := local.Peers().Get(remote.NodeInfo().ID()).(*peer)
	require.True(t, p.IsPersistent())
	// Remove the redial schedule for this test; the established peer still carries
	// the persistent flag and must remain subject to policy.
	require.NoError(t, local.AddPersistentPeers(nil))
	policy.denied.Store(true)
	require.False(t, p.send(testCh, &pp.PexRequest{}, func(byte, []byte) bool { t.Fatal("denied send reached queue"); return true }))
	require.Eventually(t, func() bool { return local.Peers().Size() == 0 }, time.Second, 10*time.Millisecond)
	require.ErrorContains(t, local.DialPeerWithAddress(remote.NetAddress()), "connection rejected by peer policy")
}

func TestConnectionPolicyCloseOnce(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(map[bool]string{false: "open", true: "closed"}[closed], func(t *testing.T) {
			rp := &remotePeer{PrivKey: ed25519.GenPrivKey(), Config: cfg}
			rp.Start()
			t.Cleanup(rp.Stop)
			p, err := createOutboundPeerAndPerformHandshake(rp.Addr(), cfg, conn.DefaultMConnConfig())
			require.NoError(t, err)
			policy := &connectionPolicy{}
			policy.denied.Store(true)
			p.policy = policy
			var output bytes.Buffer
			p.SetLogger(log.NewTMLogger(&output))
			if closed {
				require.NoError(t, p.CloseConn())
			}
			require.False(t, p.allowConnection())
			require.False(t, p.allowConnection())
			require.Equal(t, 1, strings.Count(output.String(), "Closing peer connection by policy"))
			require.Equal(t, closed, strings.Contains(output.String(), "err="))
		})
	}
}
