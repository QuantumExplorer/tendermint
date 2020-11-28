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
	GetPubKeyAtHeight(height int64) (crypto.PubKey, error)
	GetPrivateKeyAtHeight(height int64) (crypto.PrivKey, error)

    UpdatePrivateKey(privateKey crypto.PrivKey, height int64) error

	GetProTxHash() (crypto.ProTxHash, error)

	SignVote(chainID string, vote *tmproto.Vote) error
	SignProposal(chainID string, proposal *tmproto.Proposal) error

    ExtractIntoValidator() *Validator
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
	PreviousPrivKeyHeights []int64
	PreviousPrivKeys       []crypto.PrivKey
	ProTxHash			   crypto.ProTxHash
	breakProposalSigning   bool
	breakVoteSigning       bool
}

func NewMockPV() MockPV {
	return MockPV{bls12381.GenPrivKey(), nil, nil, crypto.RandProTxHash(), false, false}
}

// NewMockPVWithParams allows one to create a MockPV instance, but with finer
// grained control over the operation of the mock validator. This is useful for
// mocking test failures.
func NewMockPVWithParams(privKey crypto.PrivKey, proTxHash []byte, breakProposalSigning, breakVoteSigning bool) MockPV {
	return MockPV{privKey, nil, nil, proTxHash, breakProposalSigning, breakVoteSigning}
}

// Implements PrivValidator.
func (pv MockPV) GetPubKey() (crypto.PubKey, error) {
	return pv.PrivKey.PubKey(), nil
}

func (pv MockPV) GetPubKeyAtHeight(height int64) (crypto.PubKey, error) {
	privateKey, err := pv.GetPrivateKeyAtHeight(height)
	if err != nil {
		return nil, err
	}
	return privateKey.PubKey(), nil
}

// Implements PrivValidator.
func (pv MockPV) GetProTxHash() (crypto.ProTxHash, error) {
	return pv.ProTxHash, nil
}

// Implements PrivValidator.
func (pv MockPV) SignVote(chainID string, vote *tmproto.Vote) error {
	useChainID := chainID
	if pv.breakVoteSigning {
		useChainID = "incorrect-chain-id"
	}

	blockSignBytes := VoteBlockSignBytes(useChainID, vote)
	stateSignBytes := VoteStateSignBytes(useChainID, vote)
	privateKey, err := pv.GetPrivateKeyAtHeight(vote.Height)
	if err != nil {
		return err
	}
	blockSignature, err := privateKey.Sign(blockSignBytes)
	//fmt.Printf("block sign bytes are %X by %X using key %X resulting in sig %X\n", blockSignBytes, pv.ProTxHash, pv.PrivKey.PubKey().Bytes(), blockSignature)
	if err != nil {
		return err
	}
	vote.BlockSignature = blockSignature

	if stateSignBytes != nil {
		stateSignature, err := privateKey.Sign(stateSignBytes)
		if err != nil {
			return err
		}
		vote.StateSignature = stateSignature
	}

	return nil
}

// Implements PrivValidator.
func (pv MockPV) SignProposal(chainID string, proposal *tmproto.Proposal) error {
	useChainID := chainID
	if pv.breakProposalSigning {
		useChainID = "incorrect-chain-id"
	}

	signBytes := ProposalBlockSignBytes(useChainID, proposal)
	privateKey, err := pv.GetPrivateKeyAtHeight(proposal.Height)
	if err != nil {
		return err
	}
	sig, err := privateKey.Sign(signBytes)
	if err != nil {
		return err
	}

	proposal.Signature = sig

	return nil
}

func (pv MockPV) GetPrivateKeyAtHeight(height int64) (crypto.PrivKey, error) {
	//Lets imagine we originally have key A and we update it to key B at height 10 and then key C at height 15
	//We would then have :
	// Keys:    A    B    C
	// Heights: 10   15   current
	//The key before 15 is B (at 15 it is C)
	//The key before 10 is A
	keyAtHeight := pv.PrivKey
	for i := len(pv.PreviousPrivKeyHeights) - 1; i>-1; i-- {
		keyHeight := pv.PreviousPrivKeyHeights[i]
		if keyHeight > height {
			keyAtHeight = pv.PreviousPrivKeys[i]
		} else {
			break
		}
	}
	return keyAtHeight, nil
}

func (pv MockPV) UpdatePrivateKey(privateKey crypto.PrivKey, height int64) error {
	if len(pv.PreviousPrivKeyHeights) > 0 {
		//we need to verify that the new height is superior to the last height of the previous private keys
		if pv.PreviousPrivKeyHeights[len(pv.PreviousPrivKeyHeights) - 1] > height {
			return errors.New("the private key must be supplied for a new height")
		} else if pv.PreviousPrivKeyHeights[len(pv.PreviousPrivKeyHeights) - 1] == height {
			//we should make sure we are trying to update the same hey for the same height
			if !pv.PreviousPrivKeys[len(pv.PreviousPrivKeyHeights) - 1].Equals(privateKey) {
				return errors.New("error trying to modify a private key for a height already defined")
			}
		}
	}
	pv.PreviousPrivKeys = append(pv.PreviousPrivKeys, pv.PrivKey)
	pv.PreviousPrivKeyHeights = append(pv.PreviousPrivKeyHeights, height)
	pv.PrivKey = privateKey
	return nil
}

func (pv MockPV) ExtractIntoValidator() *Validator {
	pubKey, _ := pv.GetPubKey()
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
func (pv MockPV) String() string {
	mpv, _ := pv.GetPubKey() // mockPV will never return an error, ignored here
	return fmt.Sprintf("MockPV{%v}", mpv.Address())
}

// XXX: Implement.
func (pv MockPV) DisableChecks() {
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
	return &ErroringMockPV{MockPV{bls12381.GenPrivKey(), nil, nil, crypto.RandProTxHash(), false, false}}
}

type MockPrivValidatorsByProTxHash []MockPV

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
