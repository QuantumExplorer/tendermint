package bls12381_test

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/bls12381"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSignAndValidateBLS12381(t *testing.T) {

	privKey := bls12381.GenPrivKey()
	pubKey := privKey.PubKey()

	msg := crypto.CRandBytes(128)
	sig, err := privKey.Sign(msg)
	require.Nil(t, err)

	// Test the signature
	assert.True(t, pubKey.VerifySignature(msg, sig))
}

func TestBLSAddress(t *testing.T) {
	decodedPrivateKeyBytes, err := base64.StdEncoding.DecodeString("RokcLOxJWTyBkh5HPbdIACng/B65M8a5PYH1Nw6xn70=")
	require.Nil(t, err)
	decodedPublicKeyBytes, err := base64.StdEncoding.DecodeString("F5BjXeh0DppqaxX7a3LzoWr6CXPZcZeba6VHYdbiUCxQ23b00mFD8FRZpCz9Ug1E")
	require.Nil(t, err)
	decodedAddressBytes, err := hex.DecodeString("DDAD59BB10A10088C5A9CA219C3CF5BB4599B54E")
	require.Nil(t, err)
	privKey := bls12381.PrivKey(decodedPrivateKeyBytes)
	pubKey := privKey.PubKey()
	address := pubKey.Address()
	assert.EqualValues(t, decodedPublicKeyBytes, pubKey)
	assert.EqualValues(t, decodedAddressBytes, address)
}

func TestAggregationDiffMessages(t *testing.T) {
	privKey := bls12381.GenPrivKey()
	pubKey := privKey.PubKey()
	msg1 := crypto.CRandBytes(128)
	msg2 := crypto.CRandBytes(128)
	msg3 := crypto.CRandBytes(128)
	sig1, err := privKey.Sign(msg1)
	require.Nil(t, err)
	sig2, err := privKey.Sign(msg2)
	require.Nil(t, err)
	sig3, err := privKey.Sign(msg3)
	require.Nil(t, err)

	// Test the signature
	assert.True(t, pubKey.VerifySignature(msg1, sig1))
	assert.True(t, pubKey.VerifySignature(msg2, sig2))
	assert.True(t, pubKey.VerifySignature(msg3, sig3))

	var signatures [][]byte
	var wrongSignatures [][]byte
	var messages [][]byte
	var wrongMessages [][]byte
	signatures = append(signatures, sig1)
	signatures = append(signatures, sig2)
	wrongSignatures = append(wrongSignatures, sig1)
	wrongSignatures = append(wrongSignatures, sig3)
	messages = append(messages, msg1)
	messages = append(messages, msg2)
	wrongMessages = append(wrongMessages, msg1)
	wrongMessages = append(wrongMessages, msg3)

	aggregateSignature, err := pubKey.AggregateSignatures(signatures, messages)
	require.Nil(t, err)
	wrongAggregateSignature, err := pubKey.AggregateSignatures(wrongSignatures, messages)
	require.Nil(t, err)

	assert.True(t, pubKey.VerifyAggregateSignature(messages, aggregateSignature))
	assert.False(t, pubKey.VerifyAggregateSignature(wrongMessages, aggregateSignature))
	assert.False(t, pubKey.VerifyAggregateSignature(messages, wrongAggregateSignature))
}
