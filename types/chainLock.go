package types

import (
	tmproto "github.com/quantumexplorer/tendermint/proto/tendermint/types"
)

type ChainLock struct {
	CoreBlockHeight    uint32          `json:"core_block_height"`   // height of Chain Lock.
	CoreBlockHash      []byte         `json:"core_block_hash"`     // hash of Chain Lock.
	Signature          []byte         `json:"signature"`           // signature.
}

// ToProto converts Header to protobuf
func (cl *ChainLock) ToProto() *tmproto.ChainLock {
	if cl == nil {
		return nil
	}

	return &tmproto.ChainLock{
		CoreBlockHeight:         cl.CoreBlockHeight,
		CoreBlockHash:           cl.CoreBlockHash,
		Signature:               cl.Signature,
	}
}

func NewMockChainLock() ChainLock {
	return ChainLock{
		CoreBlockHeight: 1,
	}
}
