package consensus

import (
	"bytes"
	"context"
	"fmt"

	"github.com/cometbft/cometbft/types"
)

// verifyVoteExtension authenticates before calling the application, including for late votes
// whose signer belongs to the previous validator set.
func (cs *State) verifyVoteExtension(vote *types.Vote, validators *types.ValidatorSet) error {
	if validators == nil {
		return ErrInvalidVote{Reason: "validator set is unavailable"}
	}
	_, val := validators.GetByIndex(vote.ValidatorIndex)
	if val == nil {
		return ErrInvalidVote{Reason: fmt.Sprintf("ValidatorIndex %d is out of bounds [0, %d)", vote.ValidatorIndex, validators.Size())}
	}
	if err := vote.VerifyExtension(cs.state.ChainID, val.PubKey); err != nil {
		return err
	}
	err := cs.blockExec.VerifyVoteExtension(context.TODO(), vote)
	cs.metrics.MarkVoteExtensionReceived(err == nil)
	return err
}

// lastCommitHas reports whether LastCommit holds a vote with this signature from the same validator.
// A copy with a different extension is still not added, since AddVote compares signatures first.
func (cs *State) lastCommitHas(vote *types.Vote) bool {
	if vote.ValidatorIndex < 0 || int(vote.ValidatorIndex) >= cs.LastCommit.Size() {
		return false
	}
	existing := cs.LastCommit.GetByIndex(vote.ValidatorIndex)
	return existing != nil && bytes.Equal(existing.Signature, vote.Signature)
}
