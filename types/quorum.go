package types

import (
	"github.com/tendermint/tendermint/crypto"
)

type PrivLLMQ struct {
	members          int
	threshold        int
	proTxHashes      []crypto.ProTxHash
	secretKeyShares  []crypto.PrivKey //In the order of the LLMQ
	publicKey        *crypto.PubKey
}
