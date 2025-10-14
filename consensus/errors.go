package consensus

import "errors"

var ErrProposalTooManyParts = errors.New("proposal block has too many parts")

type ErrInvalidVote struct {
	Reason string
}

func (e ErrInvalidVote) Error() string {
	return "invalid vote: " + e.Reason
}
