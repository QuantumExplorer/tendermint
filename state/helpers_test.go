package state_test

import (
	"fmt"
	"github.com/tendermint/tendermint/crypto/bls12381"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
	dbm "github.com/tendermint/tm-db"

	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	tmstate "github.com/tendermint/tendermint/proto/tendermint/state"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	"github.com/tendermint/tendermint/proxy"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
)

type paramsChangeTestCase struct {
	height int64
	params tmproto.ConsensusParams
}

func newTestApp() proxy.AppConns {
	app := &testApp{}
	cc := proxy.NewLocalClientCreator(app)
	return proxy.NewAppConns(cc)
}

func makeAndCommitGoodBlock(
	state sm.State,
	height int64,
	lastCommit *types.Commit,
	proposerProTxHash []byte,
	blockExec *sm.BlockExecutor,
	privVals map[string]types.PrivValidator,
	evidence []types.Evidence) (sm.State, types.BlockID, types.StateID, *types.Commit, error) {
	// A good block passes
	state, blockID, stateID, err := makeAndApplyGoodBlock(state, height, lastCommit, proposerProTxHash, blockExec, evidence)
	if err != nil {
		return state, types.BlockID{}, types.StateID{}, nil, err
	}

	// Simulate a lastCommit for this block from all validators for the next height
	commit, err := makeValidCommit(height, blockID, stateID, state.Validators, privVals)
	if err != nil {
		return state, types.BlockID{}, types.StateID{}, nil, err
	}
	return state, blockID, stateID, commit, nil
}

func makeAndApplyGoodBlock(state sm.State, height int64, lastCommit *types.Commit, proposerProTxHash []byte,
	blockExec *sm.BlockExecutor, evidence []types.Evidence) (sm.State, types.BlockID, types.StateID, error) {
	block, _ := state.MakeBlock(height, makeTxs(height), lastCommit, evidence, proposerProTxHash)
	if err := blockExec.ValidateBlock(state, block); err != nil {
		return state, types.BlockID{}, types.StateID{}, err
	}
	blockID := types.BlockID{Hash: block.Hash(),
		PartSetHeader: types.PartSetHeader{Total: 3, Hash: tmrand.Bytes(32)}}
	state, _, err := blockExec.ApplyBlock(state, blockID, block)
	if err != nil {
		return state, types.BlockID{}, types.StateID{}, err
	}
	return state, blockID, types.StateID{LastAppHash: state.AppHash}, nil
}

func makeValidCommit(
	height int64,
	blockID types.BlockID,
	stateID types.StateID,
	vals *types.ValidatorSet,
	privVals map[string]types.PrivValidator,
) (*types.Commit, error) {
	sigs := make([]types.CommitSig, 0)
	for i := 0; i < vals.Size(); i++ {
		_, val := vals.GetByIndex(int32(i))
		vote, err := types.MakeVote(height, blockID, stateID, vals, privVals[val.ProTxHash.String()], chainID)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, vote.CommitSig())
	}
	return types.NewCommit(height, 0, blockID, stateID, sigs), nil
}

// make some bogus txs
func makeTxs(height int64) (txs []types.Tx) {
	for i := 0; i < nTxsPerBlock; i++ {
		txs = append(txs, types.Tx([]byte{byte(height), byte(i)}))
	}
	return txs
}

func makeState(nVals, height int) (sm.State, dbm.DB, map[string]types.PrivValidator) {
	vals := make([]types.GenesisValidator, nVals)
	privVals := make(map[string]types.PrivValidator, nVals)
	for i := 0; i < nVals; i++ {
		secret := []byte(fmt.Sprintf("test%d", i))
		pk := bls12381.GenPrivKeyFromSecret(secret)
		valAddr := pk.PubKey().Address()
		proTxHash := crypto.RandProTxHash()
		vals[i] = types.GenesisValidator{
			Address: valAddr,
			PubKey:  pk.PubKey(),
			Power:   1000,
			Name:    fmt.Sprintf("test%d", i),
			ProTxHash: proTxHash,
		}
		privVals[proTxHash.String()] = types.NewMockPVWithParams(pk, proTxHash, false, false)
	}
	s, _ := sm.MakeGenesisState(&types.GenesisDoc{
		ChainID:    chainID,
		Validators: vals,
		AppHash:    nil,
	})

	stateDB := dbm.NewMemDB()
	stateStore := sm.NewStore(stateDB)
	if err := stateStore.Save(s); err != nil {
		panic(err)
	}

	for i := 1; i < height; i++ {
		s.LastBlockHeight++
		s.LastValidators = s.Validators.Copy()
		if err := stateStore.Save(s); err != nil {
			panic(err)
		}
	}

	return s, stateDB, privVals
}

func makeBlock(state sm.State, height int64) *types.Block {
	block, _ := state.MakeBlock(
		height,
		makeTxs(state.LastBlockHeight),
		new(types.Commit),
		nil,
		state.Validators.GetProposer().ProTxHash,
	)
	return block
}

func genValSetOnProTxHashes(proTxHashes []crypto.ProTxHash) *types.ValidatorSet {
	vals := make([]*types.Validator, len(proTxHashes))
	privateKeys, thresholdPublicKey := bls12381.CreatePrivLLMQDataOnProTxHashesDefaultThreshold(proTxHashes)
	for i := 0; i < len(proTxHashes); i++ {
		vals[i] = types.NewValidator(privateKeys[i].PubKey(), types.DefaultDashVotingPower, proTxHashes[i])
	}
	return types.NewValidatorSet(vals, thresholdPublicKey)
}

func genValSet(size int) *types.ValidatorSet {
	vals := make([]*types.Validator, size)
	privateKeys, proTxHashes, thresholdPublicKey := bls12381.CreatePrivLLMQDataDefaultThreshold(size)
	for i := 0; i < size; i++ {
		vals[i] = types.NewValidator(privateKeys[i].PubKey(), types.DefaultDashVotingPower, proTxHashes[i])
	}
	return types.NewValidatorSet(vals, thresholdPublicKey)
}

func validatorUpdatesRegenerateOnProTxHashes(proTxHashes []crypto.ProTxHash) ([]abci.ValidatorUpdate, crypto.PubKey) {
	privateKeys, thresholdPublicKey := bls12381.CreatePrivLLMQDataOnProTxHashesDefaultThreshold(proTxHashes)
	var valUpdates []abci.ValidatorUpdate
	for i := 0; i < len(proTxHashes) ; i++ {
		valUpdate := types.TM2PB.NewValidatorUpdate(privateKeys[i].PubKey(), types.DefaultDashVotingPower, proTxHashes[i])
		valUpdates = append(valUpdates,valUpdate)
	}
	return valUpdates, thresholdPublicKey
}

func makeHeaderPartsResponsesValKeysRegenerate(state sm.State, regenerate bool) (types.Header, *types.ChainLock, types.BlockID, *tmstate.ABCIResponses) {
	block := makeBlock(state, state.LastBlockHeight+1)
	abciResponses := &tmstate.ABCIResponses{
		BeginBlock: &abci.ResponseBeginBlock{},
		EndBlock:   &abci.ResponseEndBlock{ValidatorUpdates: nil},
	}
	if regenerate == true {
		proTxHashes := state.Validators.GetProTxHashes()
		valUpdates, thresholdPublicKey := validatorUpdatesRegenerateOnProTxHashes(proTxHashes)
		abciThresholdPublicKey, err := cryptoenc.PubKeyToProto(thresholdPublicKey)
		if err != nil {
			panic(err)
		}
		abciResponses.EndBlock = &abci.ResponseEndBlock{
			ValidatorUpdates: valUpdates,
			ThresholdPublicKey: &abciThresholdPublicKey,
		}
	}

	return block.Header, block.ChainLock, types.BlockID{Hash: block.Hash(), PartSetHeader: types.PartSetHeader{}}, abciResponses
}

func makeHeaderPartsResponsesValPowerChange(
	state sm.State,
	power int64,
) (types.Header, *types.ChainLock, types.BlockID, *tmstate.ABCIResponses) {

	block := makeBlock(state, state.LastBlockHeight+1)
	abciResponses := &tmstate.ABCIResponses{
		BeginBlock: &abci.ResponseBeginBlock{},
		EndBlock:   &abci.ResponseEndBlock{ValidatorUpdates: nil},
	}

	// If the pubkey is new, remove the old and add the new.
	_, val := state.NextValidators.GetByIndex(0)
	if val.VotingPower != power {
		abciResponses.EndBlock = &abci.ResponseEndBlock{
			ValidatorUpdates: []abci.ValidatorUpdate{
				types.TM2PB.NewValidatorUpdate(val.PubKey, power, val.ProTxHash),
			},
		}
	}

	return block.Header, block.ChainLock, types.BlockID{Hash: block.Hash(), PartSetHeader: types.PartSetHeader{}}, abciResponses
}

func makeHeaderPartsResponsesParams(
	state sm.State,
	params tmproto.ConsensusParams,
) (types.Header, *types.ChainLock, types.BlockID, *tmstate.ABCIResponses) {

	block := makeBlock(state, state.LastBlockHeight+1)
	abciResponses := &tmstate.ABCIResponses{
		BeginBlock: &abci.ResponseBeginBlock{},
		EndBlock:   &abci.ResponseEndBlock{ConsensusParamUpdates: types.TM2PB.ConsensusParams(&params)},
	}
	return block.Header, block.ChainLock, types.BlockID{Hash: block.Hash(), PartSetHeader: types.PartSetHeader{}}, abciResponses
}

func randomGenesisDoc() *types.GenesisDoc {
	pubkey := bls12381.GenPrivKey().PubKey()
	return &types.GenesisDoc{
		GenesisTime: tmtime.Now(),
		ChainID:     "abc",
		Validators: []types.GenesisValidator{
			{
				Address: pubkey.Address(),
				PubKey:  pubkey,
				ProTxHash: crypto.CRandBytes(32),
				Power:   10,
				Name:    "myval",
			},
		},
		ConsensusParams: types.DefaultConsensusParams(),
	}
}

//----------------------------------------------------------------------------

type testApp struct {
	abci.BaseApplication

	CommitVotes         []abci.VoteInfo
	ByzantineValidators []abci.Evidence
	ValidatorUpdates    []abci.ValidatorUpdate
}

var _ abci.Application = (*testApp)(nil)

func (app *testApp) Info(req abci.RequestInfo) (resInfo abci.ResponseInfo) {
	return abci.ResponseInfo{}
}

func (app *testApp) BeginBlock(req abci.RequestBeginBlock) abci.ResponseBeginBlock {
	app.CommitVotes = req.LastCommitInfo.Votes
	app.ByzantineValidators = req.ByzantineValidators
	return abci.ResponseBeginBlock{}
}

func (app *testApp) EndBlock(req abci.RequestEndBlock) abci.ResponseEndBlock {
	return abci.ResponseEndBlock{
		ValidatorUpdates: app.ValidatorUpdates,
		ConsensusParamUpdates: &abci.ConsensusParams{
			Version: &tmproto.VersionParams{
				AppVersion: 1}}}
}

func (app *testApp) DeliverTx(req abci.RequestDeliverTx) abci.ResponseDeliverTx {
	return abci.ResponseDeliverTx{Events: []abci.Event{}}
}

func (app *testApp) CheckTx(req abci.RequestCheckTx) abci.ResponseCheckTx {
	return abci.ResponseCheckTx{}
}

func (app *testApp) Commit() abci.ResponseCommit {
	return abci.ResponseCommit{RetainHeight: 1}
}

func (app *testApp) Query(reqQuery abci.RequestQuery) (resQuery abci.ResponseQuery) {
	return
}
