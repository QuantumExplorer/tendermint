package bls12381

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"

	bls "github.com/quantumexplorer/bls-signatures/go-bindings"

	"github.com/quantumexplorer/tendermint/crypto"
	"github.com/quantumexplorer/tendermint/crypto/tmhash"
	tmjson "github.com/quantumexplorer/tendermint/libs/json"
)

//-------------------------------------

var _ crypto.PrivKey = PrivKey{}

const (
	PrivKeyName = "tendermint/PrivKeyBLS12381"
	PubKeyName  = "tendermint/PubKeyBLS12381"
	// PubKeySize is is the size, in bytes, of public keys as used in this package.
	PubKeySize = 48
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 32
	// Size of an BLS12381 signature.
	SignatureSize = 96
	// SeedSize is the size, in bytes, of private key seeds. These are the
	// private key representations used by RFC 8032.
	SeedSize = 32

	keyType = "bls12381"
)

func init() {
	tmjson.RegisterType(PubKey{}, PubKeyName)
	tmjson.RegisterType(PrivKey{}, PrivKeyName)
}

// PrivKey implements crypto.PrivKey.
type PrivKey []byte

// Bytes returns the privkey byte format.
func (privKey PrivKey) Bytes() []byte {
	return []byte(privKey)
}

// Sign produces a signature on the provided message.
// This assumes the privkey is wellformed in the golang format.
// The first 32 bytes should be random,
// corresponding to the normal bls12381 private key.
// The latter 32 bytes should be the compressed public key.
// If these conditions aren't met, Sign will panic or produce an
// incorrect signature.
func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	blsPrivateKey, _ := bls.PrivateKeyFromBytes(privKey,false)
	insecureSignature := blsPrivateKey.SignInsecure(msg)
	return insecureSignature.Serialize(), nil
}

// PubKey gets the corresponding public key from the private key.
//
// Panics if the private key is not initialized.
func (privKey PrivKey) PubKey() crypto.PubKey {
	blsPrivateKey, _ := bls.PrivateKeyFromBytes(privKey,false)
	publicKeyBytes := blsPrivateKey.PublicKey().Serialize()
	return PubKey(publicKeyBytes)
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
	if otherBLS, ok := other.(PrivKey); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherBLS[:]) == 1
	}

	return false
}

func (privKey PrivKey) TypeIdentifier() string {
	return keyType
}

func (privKey PrivKey) Type() crypto.KeyType {
	return crypto.BLS12381
}

// GenPrivKey generates a new bls12381 private key.
// It uses OS randomness in conjunction with the current global random seed
// in tendermint/libs/common to generate the private key.
func GenPrivKey() PrivKey {
	return genPrivKey(crypto.CReader())
}

// genPrivKey generates a new bls12381 private key using the provided reader.
func genPrivKey(rand io.Reader) PrivKey {
	seed := make([]byte, SeedSize)

	_, err := io.ReadFull(rand, seed)
	if err != nil {
		panic(err)
	}

	return PrivKey(bls.PrivateKeyFromSeed(seed).Serialize())
}

// GenPrivKeyFromSecret hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeyFromSecret(secret []byte) PrivKey {
	seed := crypto.Sha256(secret) // Not Ripemd160 because we want 32 bytes.

	return PrivKey(bls.PrivateKeyFromSeed(seed).Serialize())
}

//-------------------------------------

var _ crypto.PubKey = PubKey{}

// PubKeyBLS12381 implements crypto.PubKey for the bls12381 signature scheme.
type PubKey []byte

// Address is the SHA256-20 of the raw pubkey bytes.
func (pubKey PubKey) Address() crypto.Address {
	if len(pubKey) != PubKeySize {
		panic("pubkey is incorrect size")
	}
	return crypto.Address(tmhash.SumTruncated(pubKey))
}

// Bytes returns the PubKey byte format.
func (pubKey PubKey) Bytes() []byte {
	return []byte(pubKey)
}

func (pubKey PubKey) VerifyBytes(msg []byte, sig []byte) bool {
	// make sure we use the same algorithm to sign
	if len(sig) != SignatureSize {
		return false
	}
	publicKey, _ := bls.PublicKeyFromBytes(pubKey)
	aggregationInfo := bls.AggregationInfoFromMsg(publicKey,msg)
	blsSignature, _ := bls.SignatureFromBytesWithAggregationInfo(sig,aggregationInfo)
	return blsSignature.Verify()
}

func (pubKey PubKey) String() string {
	return fmt.Sprintf("PubKeyBLS12381{%X}", []byte(pubKey))
}

func (pubKey PubKey) TypeIdentifier() string {
	return keyType
}

func (pubKey PubKey) Type() crypto.KeyType {
	return crypto.BLS12381
}

func (pubKey PubKey) Equals(other crypto.PubKey) bool {
	if otherBLS, ok := other.(PubKey); ok {
		return bytes.Equal(pubKey[:], otherBLS[:])
	}

	return false
}
