package crypto

import (
	"github.com/tendermint/tendermint/crypto/tmhash"
	"github.com/tendermint/tendermint/libs/bytes"
)

const (
	// AddressSize is the size of a pubkey address.
	AddressSize = tmhash.TruncatedSize
	DefaultHashSize = 32
)

type KeyType int

const (
	Ed25519 KeyType = iota
	BLS12381
	Sr25519
	Secp256k1
	KeyTypeAny
)

// An address is a []byte, but hex-encoded even in JSON.
// []byte leaves us the option to change the address length.
// Use an alias so Unmarshal methods (with ptr receivers) are available too.
type Address = bytes.HexBytes

type ProTxHash = bytes.HexBytes

func AddressHash(bz []byte) Address {
	return Address(tmhash.SumTruncated(bz))
}

func ProTxHashFromSeedBytes(bz []byte) ProTxHash {
	return ProTxHash(tmhash.Sum(bz))
}

func RandProTxHash() ProTxHash {
	return ProTxHash(CRandBytes(32))
}

type PubKey interface {
	Address() Address
	Bytes() []byte
	VerifySignature(msg []byte, sig []byte) bool
    AggregateSignatures(sigSharesData [][]byte, messages [][]byte) ([]byte, error)
	VerifyAggregateSignature(msgs [][]byte, sig []byte) bool
	Equals(PubKey) bool
	TypeIdentifier() string
	Type() KeyType
}

type PrivKey interface {
	Bytes() []byte
	Sign(msg []byte) ([]byte, error)
	PubKey() PubKey
	Equals(PrivKey) bool
	TypeIdentifier() string
	Type() KeyType
}

type Symmetric interface {
	Keygen() []byte
	Encrypt(plaintext []byte, secret []byte) (ciphertext []byte)
	Decrypt(ciphertext []byte, secret []byte) (plaintext []byte, err error)
}
