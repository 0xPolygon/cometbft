package rpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The offline inspect server has no live consensus reactor, so it always reports
// fully synced: never waiting on block-sync and never behind its peers.
func TestWaitSyncCheckerReportsSynced(t *testing.T) {
	checker := waitSyncCheckerImpl{}
	assert.False(t, checker.WaitSync())
	assert.False(t, checker.IsBehind())
}
