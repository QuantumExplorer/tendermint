package bls12381

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/quantumexplorer/tendermint/crypto"
	"github.com/quantumexplorer/tendermint/crypto/bls12831"
	"testing"
)

func TestSignAndValidateBLS12381(t *testing.T) {

	privKey := bls12381()
	pubKey := privKey.PubKey()

	msg := crypto.CRandBytes(128)
	sig, err := privKey.Sign(msg)
	require.Nil(t, err)

	// Test the signature
	assert.True(t, pubKey.VerifyBytes(msg, sig))

	// Mutate the signature, just one bit.
	// TODO: Replace this with a much better fuzzer, tendermint/ed25519/issues/10
	sig[7] ^= byte(0x01)

	assert.False(t, pubKey.VerifyBytes(msg, sig))
}
