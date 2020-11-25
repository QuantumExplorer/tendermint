package types

import (
	"github.com/tendermint/tendermint/crypto/bls12381"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
)

func UpdateValidator(proTxHash []byte, pk []byte, power int64) ValidatorUpdate {
	pke := bls12381.PubKey(pk)
	pkp, err := cryptoenc.PubKeyToProto(pke)
	if err != nil {
		panic(err)
	}

	return ValidatorUpdate{
		// Address:
		PubKey: pkp,
		Power:  power,
		ProTxHash: proTxHash,
	}
}

func UpdateThresholdPublicKey(pk []byte) ThresholdPublicKeyUpdate {
	pke := bls12381.PubKey(pk)
	pkp, err := cryptoenc.PubKeyToProto(pke)
	if err != nil {
		panic(err)
	}

	return ThresholdPublicKeyUpdate{
		ThresholdPublicKey: pkp,
	}
}
