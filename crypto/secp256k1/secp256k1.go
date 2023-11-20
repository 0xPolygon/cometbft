package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"math/big"

	secp256k1 "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/cometbft/cometbft/crypto"
	cmtjson "github.com/cometbft/cometbft/libs/json"
)

// -------------------------------------
const (
	PrivKeyName = "tendermint/PrivKeySecp256k1"
	PubKeyName  = "tendermint/PubKeySecp256k1"

	KeyType     = "secp256k1"
	PrivKeySize = 32
)

func init() {
	cmtjson.RegisterType(PubKeySecp256k1{}, PubKeyName)
	cmtjson.RegisterType(PrivKeySecp256k1{}, PrivKeyName)
}

var _ crypto.PrivKey = PrivKeySecp256k1{}

// PrivKey implements PrivKey.
type PrivKeySecp256k1 []byte

// Bytes marshalls the private key using amino encoding.
func (privKey PrivKeySecp256k1) Bytes() []byte {
	return []byte(privKey)
}

// PubKey performs the point-scalar multiplication from the privKey on the
// generator point to get the pubkey.
func (privKey PrivKeySecp256k1) PubKey() crypto.PubKey {
	privateObject, err := ethCrypto.ToECDSA(privKey[:])
	if err != nil {
		panic(err)
	}

	pubKeyBytes := ethCrypto.FromECDSAPub(&privateObject.PublicKey)
	return PubKeySecp256k1(pubKeyBytes)

	// _, pubkeyObject := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey[:])
	// var pubkeyBytes PubKeySecp256k1
	// copy(pubkeyBytes[:], pubkeyObject.SerializeCompressed())
	// return pubkeyBytes
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKeySecp256k1) Equals(other crypto.PrivKey) bool {
	if otherSecp, ok := other.(PrivKeySecp256k1); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherSecp[:]) == 1
	}
	return false
}

func (privKey PrivKeySecp256k1) Type() string {
	return KeyType
}

// GenPrivKey generates a new ECDSA private key on curve secp256k1 private key.
// It uses OS randomness to generate the private key.
func GenPrivKey() PrivKeySecp256k1 {
	return genPrivKey(crypto.CReader())
}

// genPrivKey generates a new secp256k1 private key using the provided reader.
func genPrivKey(rand io.Reader) PrivKeySecp256k1 {
	// var privKeyBytes [32]byte
	// d := new(big.Int)
	// for {
	// 	privKeyBytes = [32]byte{}
	// 	_, err := io.ReadFull(rand, privKeyBytes[:])
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	d.SetBytes(privKeyBytes[:])
	// 	// break if we found a valid point (i.e. > 0 and < N == curverOrder)
	// 	isValidFieldElement := 0 < d.Sign() && d.Cmp(secp256k1.S256().N) < 0
	// 	if isValidFieldElement {
	// 		break
	// 	}
	// }

	// return PrivKeySecp256k1(privKeyBytes)

	privKeyBytes := [PrivKeySize]byte{}
	_, err := io.ReadFull(rand, privKeyBytes[:])
	if err != nil {
		panic(err)
	}
	// crypto.CRandBytes is guaranteed to be 32 bytes long, so it can be
	// casted to PrivKeySecp256k1.
	return PrivKeySecp256k1(privKeyBytes[:])
}

var one = new(big.Int).SetInt64(1)

// GenPrivKeySecp256k1 hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
//
// It makes sure the private key is a valid field element by setting:
//
// c = sha256(secret)
// k = (c mod (n − 1)) + 1, where n = curve order.
//
// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeySecp256k1(secret []byte) PrivKeySecp256k1 {
	secHash := sha256.Sum256(secret)
	// to guarantee that we have a valid field element, we use the approach of:
	// "Suite B Implementer’s Guide to FIPS 186-3", A.2.1
	// https://apps.nsa.gov/iaarchive/library/ia-guidance/ia-solutions-for-classified/algorithm-guidance/suite-b-implementers-guide-to-fips-186-3-ecdsa.cfm
	// see also https://github.com/golang/go/blob/0380c9ad38843d523d9c9804fe300cb7edd7cd3c/src/crypto/ecdsa/ecdsa.go#L89-L101
	fe := new(big.Int).SetBytes(secHash[:])
	n := new(big.Int).Sub(secp256k1.S256().N, one)
	fe.Mod(fe, n)
	fe.Add(fe, one)

	feB := fe.Bytes()
	privKey32 := make([]byte, PrivKeySize)
	// copy feB over to fixed 32 byte privKey32 and pad (if necessary)
	copy(privKey32[32-len(feB):32], feB)

	return PrivKeySecp256k1(privKey32)
}

// Sign creates an ECDSA signature on curve Secp256k1, using SHA256 on the msg.
// The returned signature will be of the form R || S (in lower-S form).
// func (privKey PrivKeySecp256k1) Sign(msg []byte) ([]byte, error) {
// 	priv, _ := secp256k1.PrivKeyFromBytes(privKey)

// 	sig, err := ecdsa.SignCompact(priv, crypto.Sha256(msg), false)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// remove the first byte which is compactSigRecoveryCode
// 	return sig[1:], nil
// }

//-------------------------------------

var _ crypto.PubKey = PubKeySecp256k1{}

// PubKeySize is comprised of 32 bytes for one field element
// (the x-coordinate), plus one byte for the parity of the y-coordinate.
// const PubKeySecp256k1Size = 33
const PubKeySecp256k1Size = 65

// PubKey implements crypto.PubKey.
// It is the compressed form of the pubkey. The first byte depends is a 0x02 byte
// if the y-coordinate is the lexicographically largest of the two associated with
// the x-coordinate. Otherwise the first byte is a 0x03.
// This prefix is followed with the x-coordinate.
type PubKeySecp256k1 []byte

// Address returns a Bitcoin style addresses: RIPEMD160(SHA256(pubkey))
func (pubKey PubKeySecp256k1) Address() crypto.Address {
	// hasherSHA256 := sha256.New()
	// hasherSHA256.Write(pubKey[:]) // does not error
	// sha := hasherSHA256.Sum(nil)

	// hasherRIPEMD160 := ripemd160.New()
	// hasherRIPEMD160.Write(sha) // does not error
	// return crypto.Address(hasherRIPEMD160.Sum(nil))
	return crypto.Address(ethCrypto.Keccak256(pubKey[1:])[12:])

}

// Bytes returns the pubkey marshaled with amino encoding.
func (pubKey PubKeySecp256k1) Bytes() []byte {
	return []byte(pubKey)
}

func (pubKey PubKeySecp256k1) String() string {
	return fmt.Sprintf("PubKeySecp256k1{%X}", []byte(pubKey))
}

func (pubKey PubKeySecp256k1) Equals(other crypto.PubKey) bool {
	if otherSecp, ok := other.(PubKeySecp256k1); ok {
		return bytes.Equal(pubKey[:], otherSecp[:])
	}
	return false
}

func (pubKey PubKeySecp256k1) Type() string {
	return KeyType
}

// VerifySignature verifies a signature of the form R || S.
// It rejects signatures which are not in lower-S form.
func (pubKey PubKeySecp256k1) VerifySignature(msg []byte, sigStr []byte) bool {
	// if len(sigStr) != 64 {
	// 	return false
	// }
	// pub, err := secp256k1.ParsePubKey(pubKey[:], secp256k1.S256())
	// if err != nil {
	// 	return false
	// }
	// // parse the signature:
	// signature := signatureFromBytes(sigStr)
	// // Reject malleable signatures. libsecp256k1 does this check but btcec doesn't.
	// // see: https://github.com/ethereum/go-ethereum/blob/f9401ae011ddf7f8d2d95020b7446c17f8d98dc1/crypto/signature_nocgo.go#L90-L93
	// if signature.S.Cmp(secp256k1halfN) > 0 {
	// 	return false
	// }
	hash := ethCrypto.Keccak256(msg)
	return ethCrypto.VerifySignature(pubKey[:], hash, sigStr[:64])
	// return signature.Verify(crypto.Sha256(msg), pub)

}

// Read Signature struct from R || S. Caller needs to ensure
// that len(sigStr) == 64.
func signatureFromBytes(sigStr []byte) *ecdsa.Signature {
	var r secp256k1.ModNScalar
	r.SetByteSlice(sigStr[:32])
	var s secp256k1.ModNScalar
	s.SetByteSlice(sigStr[32:64])
	return ecdsa.NewSignature(&r, &s)
}
