package consensus

import (
	"bytes"
	"testing"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	abci "github.com/cometbft/cometbft/abci/types"
	abcimocks "github.com/cometbft/cometbft/abci/types/mocks"
	cstypes "github.com/cometbft/cometbft/consensus/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

func TestLastCommitVoteExtensionAdmission(t *testing.T) {
	tests := []struct {
		name   string
		size   int
		accept bool
		badSig bool
	}{
		{name: "accepted application response", size: 16, accept: true},
		{name: "rejected application response", size: 16},
		{name: "large accepted vote preserves legacy admission", size: 900000, accept: true},
		{name: "large rejected vote leaves the quorum unchanged", size: 900000},
		{name: "invalid signature never reaches the application", size: 16, badSig: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app := abcimocks.NewApplication(t)
			cs, validators, hash := lastCommitVoteState(t, app)
			received := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vote_extensions_received"}, []string{"status"})
			cs.metrics.VoteExtensionReceiveCount = kitprometheus.NewCounter(received)
			vote, err := validators[1].signVote(cmtproto.PrecommitType, hash, types.PartSetHeader{Total: 1, Hash: hash},
				[]byte("extension"), bytes.Repeat([]byte{2}, tc.size), true)
			require.NoError(t, err)
			require.NoError(t, vote.ValidateBasic())
			require.Less(t, vote.ToProto().Size(), maxMsgSize)
			if tc.badSig {
				vote.NonRpExtensionSignature[0] ^= 1
			} else {
				status := abci.ResponseVerifyVoteExtension_REJECT
				if tc.accept {
					status = abci.ResponseVerifyVoteExtension_ACCEPT
				}
				app.On("VerifyVoteExtension", mock.Anything, mock.Anything).Return(&abci.ResponseVerifyVoteExtension{Status: status}, nil).Once()
			}
			added, err := cs.addVote(vote, "late-peer")
			require.Equal(t, tc.accept, added)
			if tc.accept {
				require.NoError(t, err)
				require.NotNil(t, cs.LastCommit.GetByIndex(1))
			} else {
				require.Error(t, err)
				require.Nil(t, cs.LastCommit.GetByIndex(1))
			}
			require.True(t, cs.LastCommit.HasTwoThirdsMajority())
			if tc.badSig {
				app.AssertNotCalled(t, "VerifyVoteExtension", mock.Anything, mock.Anything)
			}
			for _, status := range []string{"accepted", "rejected"} {
				want := float64(0)
				if !tc.badSig && (status == "accepted") == tc.accept {
					want = 1
				}
				var metric dto.Metric
				require.NoError(t, received.WithLabelValues(status).Write(&metric))
				require.Equal(t, want, metric.GetCounter().GetValue())
			}
		})
	}
}

func TestVerifyVoteExtensionAuthenticatesSigner(t *testing.T) {
	for _, name := range []string{"missing set", "unknown index", "invalid extension signature", "invalid non-rp signature"} {
		t.Run(name, func(t *testing.T) {
			app := abcimocks.NewApplication(t)
			cs, validators, hash := lastCommitVoteState(t, app)
			vote, err := validators[1].signVote(cmtproto.PrecommitType, hash, types.PartSetHeader{Total: 1, Hash: hash},
				[]byte("extension"), []byte("non-rp"), true)
			require.NoError(t, err)
			set := cs.LastValidators
			switch name {
			case "missing set":
				set = nil
			case "unknown index":
				vote.ValidatorIndex = int32(set.Size())
			case "invalid extension signature":
				vote.ExtensionSignature[0] ^= 1
			case "invalid non-rp signature":
				vote.NonRpExtensionSignature[0] ^= 1
			}
			require.Error(t, cs.verifyVoteExtension(vote, set))
			app.AssertNotCalled(t, "VerifyVoteExtension", mock.Anything, mock.Anything)
		})
	}
}

func lastCommitVoteState(t *testing.T, app abci.Application) (*State, []*validatorStub, []byte) {
	t.Helper()
	cs, validators := randStateWithApp(4, app, false)
	t.Cleanup(func() { require.NoError(t, cs.eventBus.Stop()) })
	height := cs.Height
	cs.state.ConsensusParams.ABCI.VoteExtensionsEnableHeight = height
	cs.LastValidators = cs.Validators.Copy()
	cs.LastCommit = types.NewExtendedVoteSet(cs.state.ChainID, height, 0, cmtproto.PrecommitType, cs.LastValidators)
	cs.Height, cs.Step = height+1, cstypes.RoundStepNewHeight
	cs.config.SkipTimeoutCommit = false
	hash := bytes.Repeat([]byte{1}, 32)
	for _, index := range []int{0, 2, 3} {
		validators[index].Height = height
		vote, err := validators[index].signVote(cmtproto.PrecommitType, hash, types.PartSetHeader{Total: 1, Hash: hash},
			[]byte("extension"), []byte("non-rp"), true)
		require.NoError(t, err)
		added, err := cs.LastCommit.AddVote(vote)
		require.NoError(t, err)
		require.True(t, added)
	}
	// The current set can differ from the set that signed the previous block.
	cs.state.Validators = types.NewValidatorSet([]*types.Validator{types.NewValidator(types.NewMockPV().PrivKey.PubKey(), 10)})
	return cs, validators, hash
}

// A precommit for the current height that the application rejects is not counted.
func TestCurrentPrecommitHonorsApplicationRejection(t *testing.T) {
	app := abcimocks.NewApplication(t)
	cs, validators, hash := lastCommitVoteState(t, app)
	cs.Height--
	cs.Step = cstypes.RoundStepPrecommit
	cs.state.Validators = cs.LastValidators
	vote, err := validators[1].signVote(cmtproto.PrecommitType, hash, types.PartSetHeader{Total: 1, Hash: hash}, []byte("extension"), []byte("non-rp"), true)
	require.NoError(t, err)
	app.On("VerifyVoteExtension", mock.Anything, mock.Anything).Return(&abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_REJECT}, nil).Once()
	added, err := cs.addVote(vote, "current-peer")
	require.Error(t, err)
	require.False(t, added)
	require.Nil(t, cs.Votes.Precommits(vote.Round).GetByIndex(1))
}

// A repeated late precommit is dropped as a duplicate without a second signature check or ABCI call.
func TestLateDuplicatePrecommitSkipsVerification(t *testing.T) {
	app := abcimocks.NewApplication(t)
	cs, validators, hash := lastCommitVoteState(t, app)
	vote, err := validators[1].signVote(cmtproto.PrecommitType, hash, types.PartSetHeader{Total: 1, Hash: hash}, []byte("extension"), []byte("non-rp"), true)
	require.NoError(t, err)
	app.On("VerifyVoteExtension", mock.Anything, mock.Anything).Return(&abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_ACCEPT}, nil).Once()
	added, err := cs.addVote(vote, "late-peer")
	require.NoError(t, err)
	require.True(t, added)

	duplicate := vote.Copy()
	duplicate.Extension = []byte("unsigned extension")
	added, err = cs.addVote(duplicate, "other-peer")
	require.NoError(t, err)
	require.False(t, added)
	require.Equal(t, []byte("extension"), cs.LastCommit.GetByIndex(1).Extension)
}
