package types

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/bls12381"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
)

// PrivValidator defines the functionality of a local Tendermint validator
// that signs votes and proposals, and never double signs.
type PrivValidator interface {
	GetPubKey() (crypto.PubKey, error)
    UpdatePrivateKey(privateKey crypto.PrivKey, height int64) error

	GetProTxHash() (crypto.ProTxHash, error)

	SignVote(chainID string, vote *tmproto.Vote) error
	SignProposal(chainID string, proposal *tmproto.Proposal) error

    ExtractIntoValidator(height int64) *Validator
}

type PrivValidatorsByProTxHash []PrivValidator

func (pvs PrivValidatorsByProTxHash) Len() int {
	return len(pvs)
}

func (pvs PrivValidatorsByProTxHash) Less(i, j int) bool {
	pvi, err := pvs[i].GetProTxHash()
	if err != nil {
		panic(err)
	}
	pvj, err := pvs[j].GetProTxHash()
	if err != nil {
		panic(err)
	}

	return bytes.Compare(pvi, pvj) == -1
}

func (pvs PrivValidatorsByProTxHash) Swap(i, j int) {
	pvs[i], pvs[j] = pvs[j], pvs[i]
}

//----------------------------------------
// MockPV

// MockPV implements PrivValidator without any safety or persistence.
// Only use it for testing.
type MockPV struct {
	PrivKey                crypto.PrivKey
	NextPrivKey            crypto.PrivKey
	NextPrivKeyHeight      int64
	ProTxHash			   crypto.ProTxHash
	breakProposalSigning   bool
	breakVoteSigning       bool
}

func NewMockPV() *MockPV {
	return &MockPV{bls12381.GenPrivKey(), nil, 0, crypto.RandProTxHash(), false, false}
}

// NewMockPVWithParams allows one to create a MockPV instance, but with finer
// grained control over the operation of the mock validator. This is useful for
// mocking test failures.
func NewMockPVWithParams(privKey crypto.PrivKey, proTxHash []byte, breakProposalSigning, breakVoteSigning bool) *MockPV {
	return &MockPV{privKey, nil, 0, proTxHash, breakProposalSigning, breakVoteSigning}
}

// Implements PrivValidator.
func (pv *MockPV) GetPubKey() (crypto.PubKey, error) {
	return pv.PrivKey.PubKey(), nil
}

// Implements PrivValidator.
func (pv *MockPV) GetProTxHash() (crypto.ProTxHash, error) {
	return pv.ProTxHash, nil
}

// Implements PrivValidator.
func (pv *MockPV) SignVote(chainID string, vote *tmproto.Vote) error {
	pv.updateKeyIfNeeded(vote.Height)
	useChainID := chainID
	if pv.breakVoteSigning {
		useChainID = "incorrect-chain-id"
	}

	blockSignBytes := VoteBlockSignBytes(useChainID, vote)
	stateSignBytes := VoteStateSignBytes(useChainID, vote)
	blockSignature, err := pv.PrivKey.Sign(blockSignBytes)
	//fmt.Printf("block sign bytes are %X by %X using key %X resulting in sig %X\n", blockSignBytes, pv.ProTxHash, pv.PrivKey.PubKey().Bytes(), blockSignature)
	if err != nil {
		return err
	}
	vote.BlockSignature = blockSignature

	if stateSignBytes != nil {
		stateSignature, err := pv.PrivKey.Sign(stateSignBytes)
		if err != nil {
			return err
		}
		vote.StateSignature = stateSignature
	}

	return nil
}

// Implements PrivValidator.
func (pv *MockPV) SignProposal(chainID string, proposal *tmproto.Proposal) error {
	pv.updateKeyIfNeeded(proposal.Height)
	useChainID := chainID
	if pv.breakProposalSigning {
		useChainID = "incorrect-chain-id"
	}

	signBytes := ProposalBlockSignBytes(useChainID, proposal)
	sig, err := pv.PrivKey.Sign(signBytes)
	if err != nil {
		return err
	}

	proposal.Signature = sig

	return nil
}

func (pv *MockPV) UpdatePrivateKey(privateKey crypto.PrivKey, height int64) error {
	pv.NextPrivKey = privateKey
	pv.NextPrivKeyHeight = height
	return nil
}

func (pv *MockPV)updateKeyIfNeeded(height int64) {
	if pv.NextPrivKey != nil && height >= pv.NextPrivKeyHeight {
		pv.PrivKey = pv.NextPrivKey
		pv.NextPrivKey = nil
		pv.NextPrivKeyHeight = 0
	}
}

func (pv *MockPV) ExtractIntoValidator(height int64) *Validator {
		var pubKey crypto.PubKey
		if height >= pv.NextPrivKeyHeight && pv.NextPrivKey != nil {
		pubKey = pv.NextPrivKey.PubKey()
	} else {
		pubKey, _ = pv.GetPubKey()
	}
		if len(pv.ProTxHash) != crypto.DefaultHashSize {
		panic("proTxHash wrong length")
	}
	return &Validator{
		Address:     pubKey.Address(),
		PubKey:      pubKey,
		VotingPower: DefaultDashVotingPower,
		ProTxHash:   pv.ProTxHash,
	}
}
// String returns a string representation of the MockPV.
func (pv *MockPV) String() string {
	mpv, _ := pv.GetPubKey() // mockPV will never return an error, ignored here
	return fmt.Sprintf("MockPV{%v}", mpv.Address())
}

// XXX: Implement.
func (pv *MockPV) DisableChecks() {
	// Currently this does nothing,
	// as MockPV has no safety checks at all.
}

type ErroringMockPV struct {
	MockPV
}

var ErroringMockPVErr = errors.New("erroringMockPV always returns an error")

// Implements PrivValidator.
func (pv *ErroringMockPV) SignVote(chainID string, vote *tmproto.Vote) error {
	return ErroringMockPVErr
}

// Implements PrivValidator.
func (pv *ErroringMockPV) SignProposal(chainID string, proposal *tmproto.Proposal) error {
	return ErroringMockPVErr
}

// NewErroringMockPV returns a MockPV that fails on each signing request. Again, for testing only.

func NewErroringMockPV() *ErroringMockPV {
	return &ErroringMockPV{MockPV{bls12381.GenPrivKey(), nil, 0, crypto.RandProTxHash(), false, false}}
}

type MockPrivValidatorsByProTxHash []*MockPV

func (pvs MockPrivValidatorsByProTxHash) Len() int {
	return len(pvs)
}

func (pvs MockPrivValidatorsByProTxHash) Less(i, j int) bool {
	pvi, err := pvs[i].GetProTxHash()
	if err != nil {
		panic(err)
	}
	pvj, err := pvs[j].GetProTxHash()
	if err != nil {
		panic(err)
	}

	return bytes.Compare(pvi, pvj) == -1
}

func (pvs MockPrivValidatorsByProTxHash) Swap(i, j int) {
	pvs[i], pvs[j] = pvs[j], pvs[i]
}

type GenesisValidatorsByProTxHash []GenesisValidator

func (vs GenesisValidatorsByProTxHash) Len() int {
	return len(vs)
}

func (vs GenesisValidatorsByProTxHash) Less(i, j int) bool {
	pvi := vs[i].ProTxHash
	pvj := vs[j].ProTxHash
	return bytes.Compare(pvi, pvj) == -1
}

func (vs GenesisValidatorsByProTxHash) Swap(i, j int) {
	vs[i], vs[j] = vs[j], vs[i]
}
