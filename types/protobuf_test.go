package types

import (
	"github.com/tendermint/tendermint/crypto/bls12381"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
)

func TestABCIPubKey(t *testing.T) {
	pkBLS := bls12381.GenPrivKey().PubKey()
	err := testABCIPubKey(t, pkBLS, ABCIPubKeyTypeEd25519)
	assert.NoError(t, err)
}

func testABCIPubKey(t *testing.T, pk crypto.PubKey, typeStr string) error {
	abciPubKey, err := cryptoenc.PubKeyToProto(pk)
	require.NoError(t, err)
	pk2, err := cryptoenc.PubKeyFromProto(abciPubKey)
	require.NoError(t, err)
	require.Equal(t, pk, pk2)
	return nil
}

func TestABCIValidators(t *testing.T) {
	pkEd := bls12381.GenPrivKey().PubKey()
	proTxHash := crypto.CRandBytes(32)

	// correct validator
	tmValExpected := NewValidator(pkEd, 10, proTxHash)

	tmVal := NewValidator(pkEd, 10, proTxHash)

	abciVal := TM2PB.ValidatorUpdate(tmVal)
	tmVals, err := PB2TM.ValidatorUpdates([]abci.ValidatorUpdate{abciVal})
	assert.Nil(t, err)
	assert.Equal(t, tmValExpected, tmVals[0])

	abciVals := TM2PB.ValidatorUpdates(NewValidatorSet(tmVals))
	assert.Equal(t, []abci.ValidatorUpdate{abciVal}, abciVals)

	// val with address
	tmVal.Address = pkEd.Address()

	abciVal = TM2PB.ValidatorUpdate(tmVal)
	tmVals, err = PB2TM.ValidatorUpdates([]abci.ValidatorUpdate{abciVal})
	assert.Nil(t, err)
	assert.Equal(t, tmValExpected, tmVals[0])
}

func TestABCIConsensusParams(t *testing.T) {
	cp := DefaultConsensusParams()
	abciCP := TM2PB.ConsensusParams(cp)
	cp2 := UpdateConsensusParams(*cp, abciCP)

	assert.Equal(t, *cp, cp2)
}

func TestABCIEvidence(t *testing.T) {
	val := NewMockPV()
	blockID := makeBlockID([]byte("blockhash"), 1000, []byte("partshash"))
	blockID2 := makeBlockID([]byte("blockhash2"), 1000, []byte("partshash"))
	stateID := makeStateID([]byte("statehash"))
	const chainID = "mychain"
	pubKey, err := val.GetPubKey()
	require.NoError(t, err)
	ev := &DuplicateVoteEvidence{
		VoteA: makeVote(t, val, chainID, 0, 10, 2, 1, blockID, stateID),
		VoteB: makeVote(t, val, chainID, 0, 10, 2, 1, blockID2, stateID),
	}
	abciEv := TM2PB.Evidence(
		ev,
		NewValidatorSet([]*Validator{NewValidator(pubKey, 10, val.ProTxHash)}),
	)

	assert.Equal(t, abci.EvidenceType_DUPLICATE_VOTE, abciEv.Type)
	assert.Equal(t, ev.Height(), abciEv.GetHeight())
}

type pubKeyBLS struct{}

func (pubKeyBLS) Address() Address                        { return []byte{} }
func (pubKeyBLS) Bytes() []byte                           { return []byte{} }
func (pubKeyBLS) VerifySignature(msg []byte, sig []byte) bool { return false }
func (pubKeyBLS) AggregateSignatures(sigSharesData [][]byte, messages [][]byte) ([]byte, error) { return []byte{}, nil }
func (pubKeyBLS) VerifyAggregateSignature(msgs [][]byte, sig []byte) bool { return false }
func (pubKeyBLS) Equals(crypto.PubKey) bool               { return false }
func (pubKeyBLS) String() string                          { return "" }
func (pubKeyBLS) TypeIdentifier() string                  { return "pubKeyBLS12381" }
func (pubKeyBLS) Type() crypto.KeyType                    { return crypto.BLS12381 }

func TestABCIValidatorFromPubKeyAndPower(t *testing.T) {
	pubkey := bls12381.GenPrivKey().PubKey()

	abciVal := TM2PB.NewValidatorUpdate(pubkey, 10, crypto.CRandBytes(32))
	assert.Equal(t, int64(10), abciVal.Power)

	assert.Panics(t, func() { TM2PB.NewValidatorUpdate(nil, 10, crypto.CRandBytes(32)) })
	assert.Panics(t, func() { TM2PB.NewValidatorUpdate(pubKeyBLS{}, 10, crypto.CRandBytes(32)) })
}

func TestABCIValidatorWithoutPubKey(t *testing.T) {
	pkBLS := bls12381.GenPrivKey().PubKey()
	proTxHash := crypto.CRandBytes(32)

	abciVal := TM2PB.Validator(NewValidator(pkBLS, 10, proTxHash))

	// pubkey must be nil
	tmValExpected := abci.Validator{
		Address: pkBLS.Address(),
		Power:   10,
		ProTxHash: proTxHash,
	}

	assert.Equal(t, tmValExpected, abciVal)
}
