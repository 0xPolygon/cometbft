package types

import (
	"time"

	cmtbytes "github.com/cometbft/cometbft/libs/bytes"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttime "github.com/cometbft/cometbft/types/time"
	cmn "github.com/tendermint/tendermint/libs/common" //nolint:depguard
)

// Canonical* wraps the structs in types for amino encoding them for use in SignBytes / the Signable interface.

// TimeFormat is used for generating the sigs
const TimeFormat = time.RFC3339Nano

// TODO(@raneet10): Check whether we should keep it
type CanonicalBlockID struct {
	Hash        cmtbytes.HexBytes
	PartsHeader CanonicalPartSetHeader
}

// TODO(@raneet10): Check whether we should keep it
type CanonicalPartSetHeader struct {
	Hash  cmtbytes.HexBytes
	Total uint32
}

// TODO(@raneet10): Check whether removing Data field affects serialization
type CanonicalProposal struct {
	Type      SignedMsgType // type alias for byte
	Height    int64         `binary:"fixed64"`
	Round     int64         `binary:"fixed64"`
	POLRound  int64         `binary:"fixed64"`
	BlockID   CanonicalBlockID
	Timestamp time.Time
	ChainID   string
	Data      cmn.HexBytes // [peppermint] add data in proposal to that signers can sign
}

// TODO(@raneet10): Check whether removing Data and SideTxResults fields affect serialization
type CanonicalVote struct {
	Type      SignedMsgType // type alias for byte
	Height    int64         `binary:"fixed64"`
	Round     int64         `binary:"fixed64"`
	BlockID   CanonicalBlockID
	Timestamp time.Time
	ChainID   string

	Data          []byte         // [peppermint] tx hash
	SideTxResults []SideTxResult // [peppermint] side tx results
}

// TODO(@raneet10): Check whether removing this struct affects serialization
// CanonicalRLPVote create RLP vote to decode in contract
// [peppermint]
type CanonicalRLPVote struct {
	ChainID string
	Type    byte
	Height  uint
	Round   uint
	Data    []byte
}

//-----------------------------------
// Canonicalize the structs

func CanonicalizeBlockID(bid cmtproto.BlockID) *cmtproto.CanonicalBlockID {
	rbid, err := BlockIDFromProto(&bid)
	if err != nil {
		panic(err)
	}
	var cbid *cmtproto.CanonicalBlockID
	if rbid == nil || rbid.IsZero() {
		cbid = nil
	} else {
		cbid = &cmtproto.CanonicalBlockID{
			Hash:          bid.Hash,
			PartSetHeader: CanonicalizePartSetHeader(bid.PartSetHeader),
		}
	}

	return cbid
}

// From peppermint, will be removed eventually
func LegacyCanonicalizeBlockID(blockID BlockID) CanonicalBlockID {
	return CanonicalBlockID{
		Hash:        blockID.Hash,
		PartsHeader: LegacyCanonicalizePartSetHeader(blockID.PartSetHeader),
	}
}

// CanonicalizeVote transforms the given PartSetHeader to a CanonicalPartSetHeader.
func CanonicalizePartSetHeader(psh cmtproto.PartSetHeader) cmtproto.CanonicalPartSetHeader {
	return cmtproto.CanonicalPartSetHeader(psh)
}

// From peppermint, will be eventually removed
func LegacyCanonicalizePartSetHeader(psh PartSetHeader) CanonicalPartSetHeader {
	return CanonicalPartSetHeader{
		psh.Hash,
		psh.Total,
	}
}

// CanonicalizeVote transforms the given Proposal to a CanonicalProposal.
func CanonicalizeProposal(chainID string, proposal *cmtproto.Proposal) cmtproto.CanonicalProposal {
	return cmtproto.CanonicalProposal{
		Type:      cmtproto.ProposalType,
		Height:    proposal.Height,       // encoded as sfixed64
		Round:     int64(proposal.Round), // encoded as sfixed64
		POLRound:  int64(proposal.PolRound),
		BlockID:   CanonicalizeBlockID(proposal.BlockID),
		Timestamp: proposal.Timestamp,
		ChainID:   chainID,
	}
}

// CanonicalizeVote transforms the given Vote to a CanonicalVote, which does
// not contain ValidatorIndex and ValidatorAddress fields, or any fields
// relating to vote extensions.
func CanonicalizeVote(chainID string, vote *cmtproto.Vote) cmtproto.CanonicalVote {
	return cmtproto.CanonicalVote{
		Type:      vote.Type,
		Height:    vote.Height,       // encoded as sfixed64
		Round:     int64(vote.Round), // encoded as sfixed64
		BlockID:   CanonicalizeBlockID(vote.BlockID),
		Timestamp: vote.Timestamp,
		ChainID:   chainID,
	}
}

// From peppermint, will be removed eventually
func LegacyCanonicalizeVote(chainID string, vote *LegacyVote) CanonicalVote {
	return CanonicalVote{
		Type:      vote.Type,
		Height:    vote.Height,
		Round:     int64(vote.Round), // cast int->int64 to make amino encode it fixed64 (does not work for int)
		BlockID:   LegacyCanonicalizeBlockID(vote.BlockID),
		Timestamp: vote.Timestamp,
		ChainID:   chainID,

		SideTxResults: vote.SideTxResults,
	}
}

// CanonicalizeVoteExtension extracts the vote extension from the given vote
// and constructs a CanonicalizeVoteExtension struct, whose representation in
// bytes is what is signed in order to produce the vote extension's signature.
func CanonicalizeVoteExtension(chainID string, vote *cmtproto.Vote) cmtproto.CanonicalVoteExtension {
	return cmtproto.CanonicalVoteExtension{
		Extension: vote.Extension,
		Height:    vote.Height,
		Round:     int64(vote.Round),
		ChainId:   chainID,
	}
}

// CanonicalTime can be used to stringify time in a canonical way.
func CanonicalTime(t time.Time) string {
	// Note that sending time over amino resets it to
	// local time, we need to force UTC here, so the
	// signatures match
	return cmttime.Canonical(t).Format(TimeFormat)
}
