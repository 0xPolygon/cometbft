package consensus

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/proxy"
)

// isBehindQueryApp calls Reactor.IsBehind from Query, while the local ABCI
// client holds its mutex.
type isBehindQueryApp struct {
	abci.BaseApplication

	conR        *Reactor
	inQuery     chan struct{} // closed once Query holds the ABCI mutex
	proceed     chan struct{} // Query waits on this before calling IsBehind
	behindCalls chan bool
}

func (app *isBehindQueryApp) Query(context.Context, *abci.RequestQuery) (*abci.ResponseQuery, error) {
	close(app.inQuery)
	<-app.proceed
	app.behindCalls <- app.conR.IsBehind()
	return &abci.ResponseQuery{}, nil
}

// TestIsBehindFromABCIWithConsensusStateLocked checks that IsBehind, called
// while holding the shared ABCI mutex, returns while the consensus state lock
// is held by a goroutine waiting on that ABCI mutex.
func TestIsBehindFromABCIWithConsensusStateLocked(t *testing.T) {
	conR := newCatchupReactor(t, 100, false, 100, 100, 100)
	app := &isBehindQueryApp{
		conR:        conR,
		inQuery:     make(chan struct{}),
		proceed:     make(chan struct{}),
		behindCalls: make(chan bool, 1),
	}

	// Connections from one local client creator share a single ABCI mutex.
	cc := proxy.NewLocalClientCreator(app)
	queryConn, err := cc.NewABCIClient()
	require.NoError(t, err)
	consensusConn, err := cc.NewABCIClient()
	require.NoError(t, err)

	queryDone := make(chan error, 1)
	go func() {
		_, err := queryConn.Query(context.Background(), &abci.RequestQuery{})
		queryDone <- err
	}()
	<-app.inQuery

	holdsConsensusLock := make(chan struct{})
	verifyDone := make(chan error, 1)
	go func() {
		conR.conS.mtx.Lock()
		defer conR.conS.mtx.Unlock()
		close(holdsConsensusLock)
		_, err := consensusConn.VerifyVoteExtension(context.Background(), &abci.RequestVerifyVoteExtension{})
		verifyDone <- err
	}()
	<-holdsConsensusLock

	close(app.proceed)

	timeout := time.After(5 * time.Second)
	for _, done := range []chan error{queryDone, verifyDone} {
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-timeout:
			t.Fatal("IsBehind blocked while the consensus state lock was held")
		}
	}
	require.False(t, <-app.behindCalls)
}
