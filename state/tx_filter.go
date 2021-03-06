package state

import (
	"github.com/quantumexplorer/tendermint/crypto"
	mempl "github.com/quantumexplorer/tendermint/mempool"
	"github.com/quantumexplorer/tendermint/types"
)

// TxPreCheck returns a function to filter transactions before processing.
// The function limits the size of a transaction to the block's maximum data size.
func TxPreCheck(state State) mempl.PreCheckFunc {
	maxDataBytes := types.MaxDataBytesUnknownEvidence(
		state.ConsensusParams.Block.MaxBytes,
		crypto.BLS12381,
		state.Validators.Size(),
		state.ConsensusParams.Evidence.MaxNum,
	)
	return mempl.PreCheckMaxBytes(maxDataBytes)
}

// TxPostCheck returns a function to filter transactions after processing.
// The function limits the gas wanted by a transaction to the block's maximum total gas.
func TxPostCheck(state State) mempl.PostCheckFunc {
	return mempl.PostCheckMaxGas(state.ConsensusParams.Block.MaxGas)
}
