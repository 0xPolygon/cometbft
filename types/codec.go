package types

import (
	amino "github.com/tendermint/go-amino"                               //nolint:depguard
	cryptoAmino "github.com/tendermint/tendermint/crypto/encoding/amino" //nolint:depguard
)

var cdc = amino.NewCodec()

func init() {
	RegisterBlockAmino(cdc)
}

func RegisterBlockAmino(cdc *amino.Codec) {
	cryptoAmino.RegisterAmino(cdc)
	RegisterEvidences(cdc)
}

// GetCodec returns a codec used by the package. For testing purposes only.
func GetCodec() *amino.Codec {
	return cdc
}

// For testing purposes only
// func RegisterMockEvidencesGlobal() {
// 	RegisterMockEvidences(cdc)
// }
