package cmpdistance

import (
	"math/big"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core/tracing"
	coretypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa-geth/core/vm"
	"github.com/crytic/medusa-geth/eth/tracers"
	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/chain/types"
	fuzzerTypes "github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/logging"
	"github.com/holiman/uint256"
)

// coverageTracerResultsKey describes the key to use when storing tracer results in call message results, or when
// querying them.
const cmpDistanceTracerResultsKey = "CmpDistanceTracerResults"

// GetCmpDistanceTracerResults obtains CmpDistanceMaps stored by a CmpDistanceTracer from message results. This is nil if
// no CmpDistanceMaps were recorded by a tracer (e.g. BlockCoverageTracer was not attached during this message execution).
func GetCmpDistanceTracerResults(messageResults *types.MessageResults) *CmpDistanceMaps {
	// Try to obtain the results the tracer should've stored.
	if genericResult, ok := messageResults.AdditionalResults[cmpDistanceTracerResultsKey]; ok {
		if castedResult, ok := genericResult.(*CmpDistanceMaps); ok {
			return castedResult
		}
	}

	// If we could not obtain them, return nil.
	return nil
}

// RemoveCmpDistanceTracerResults removes CmpDistanceMaps stored by a CmpDistanceTracer from message results.
func RemoveCmpDistanceTracerResults(messageResults *types.MessageResults) {
	delete(messageResults.AdditionalResults, cmpDistanceTracerResultsKey)
}

// CmpDistanceTracer implements tracers.Tracer to collect comparison distance information
// for fuzzing campaigns from EVM execution traces.
type CmpDistanceTracer struct {
	// cmpDistanceMaps describes the comparison distance information recorded. Call frames which errored are not recorded.
	cmpDistanceMaps *CmpDistanceMaps

	// callFrameStates describes the state tracked by the tracer per call frame.
	callFrameStates []*cmpDistanceTracerCallFrameState

	// callDepth refers to the current EVM depth during tracing.
	callDepth int

	// evmContext holds the VM context during tracing
	evmContext *tracing.VMContext

	// nativeTracer is the underlying tracer used to capture EVM execution.
	nativeTracer *chain.TestChainTracer

	// codeHashCache is a cache for contract code hashes to avoid expensive recalculations.
	codeHashCache map[common.Hash]common.Hash

	// initialContractsSet records the set of contract addresses present in the base chain.
	initialContractsSet *map[common.Address]struct{}
}

var DD *uint256.Int = uint256.NewInt(1)

// cmpDistanceTracerCallFrameState tracks state across call frames in the tracer.
type cmpDistanceTracerCallFrameState struct {
	// Some fields, such as address, are not initialized until OnOpcode is called.
	// initialized tracks whether or not this has happened yet.
	initialized bool

	// create indicates whether the current call frame is executing on init bytecode (deploying a contract).
	create bool

	// pendingCmpDistanceMap describes the comparison distance maps recorded for this call frame.
	pendingCmpDistanceMap *CmpDistanceMaps

	// lookupHash describes the hash used to look up the ContractCmpDistanceMap being updated in this frame.
	lookupHash *common.Hash

	// address is used by OnOpcode to cache the result of scope.Address(), which is slow.
	// It records the address of the current contract.
	address common.Address
}

// NewCmpDistanceTracer returns a new CmpDistanceTracer.
func NewCmpDistanceTracer(contracts fuzzerTypes.Contracts) *CmpDistanceTracer {
	tracer := &CmpDistanceTracer{
		cmpDistanceMaps: NewCmpDistanceMaps(),
		callFrameStates: make([]*cmpDistanceTracerCallFrameState, 0),
		codeHashCache:   make(map[common.Hash]common.Hash),
	}

	nativeTracer := &tracers.Tracer{
		Hooks: &tracing.Hooks{
			OnTxStart: tracer.OnTxStart,
			OnEnter:   tracer.OnEnter,
			OnExit:    tracer.OnExit,
			OnOpcode:  tracer.OnOpcode,
		},
	}
	tracer.nativeTracer = &chain.TestChainTracer{Tracer: nativeTracer, CaptureTxEndSetAdditionalResults: tracer.CaptureTxEndSetAdditionalResults}

	return tracer
}

// NativeTracer returns the underlying TestChainTracer.
func (t *CmpDistanceTracer) NativeTracer() *chain.TestChainTracer {
	return t.nativeTracer
}

// SetInitialContractsSet sets the initialContractsSet value (see above).
func (t *CmpDistanceTracer) SetInitialContractsSet(initialContractsSet *map[common.Address]struct{}) {
	t.initialContractsSet = initialContractsSet
}

// BLANK_ADDRESS is an all-zero address; it's a global var so that we don't have to recalculate (and reallocate) it every time.
var BLANK_ADDRESS = common.BytesToAddress([]byte{})

// addressForCoverage modifies an address based on the initialContractsSet value.
// This is applied to all addresses before they are recorded in the distance map.
// If t.initialContractsSet is nil, we preserve all addresses.
// If t.initialContractsSet is defined, we only preserve addresses present in this set.
// Addresses not present in this set are zeroed to prevent issues with infinitely growing corpus.
func (t *CmpDistanceTracer) addressForCoverage(address common.Address) common.Address {
	if t.initialContractsSet == nil {
		return address
	} else if _, ok := (*t.initialContractsSet)[address]; ok {
		return address
	} else {
		return BLANK_ADDRESS
	}
}

// OnTxStart is called upon the start of transaction execution, as defined by tracers.Tracer.
func (t *CmpDistanceTracer) OnTxStart(vm *tracing.VMContext, tx *coretypes.Transaction, from common.Address) {
	// Reset our call frame states
	t.callDepth = 0
	t.cmpDistanceMaps = NewCmpDistanceMaps()
	t.callFrameStates = make([]*cmpDistanceTracerCallFrameState, 0)
	t.evmContext = vm
}

// OnEnter initializes the tracing operation for the top of a call frame, as defined by tracers.Tracer.
func (t *CmpDistanceTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// Check to see if this is the top level call frame
	isTopLevelFrame := depth == 0

	// Increment call frame depth if it is not the top level call frame
	if !isTopLevelFrame {
		t.callDepth++
	}

	// Create our state tracking struct for this frame.
	t.callFrameStates = append(t.callFrameStates, &cmpDistanceTracerCallFrameState{
		create:                typ == byte(vm.CREATE) || typ == byte(vm.CREATE2),
		pendingCmpDistanceMap: NewCmpDistanceMaps(),
	})
}

// OnExit is called after a call to finalize tracing completes for the top of a call frame, as defined by tracers.Tracer.
func (t *CmpDistanceTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	currentCallFrameState := t.callFrameStates[t.callDepth]
	currentDistanceMap := currentCallFrameState.pendingCmpDistanceMap

	if reverted {
		currentDistanceMap.RevertAll()
	}

	// Check to see if this is the top level call frame
	isTopLevelFrame := depth == 0

	// Commit all our distance maps up one call frame.
	var distanceUpdateErr error
	if isTopLevelFrame {
		// Update the final distance map if this is the top level call frame
		_, distanceUpdateErr = t.cmpDistanceMaps.Update(currentDistanceMap)
	} else {
		// Move distance up one call frame
		_, distanceUpdateErr = t.callFrameStates[t.callDepth-1].pendingCmpDistanceMap.Update(currentDistanceMap)

		// Pop the state tracking struct for this call frame off the stack and decrement the call depth
		t.callFrameStates = t.callFrameStates[:t.callDepth]
		t.callDepth--
	}
	if distanceUpdateErr != nil {
		logging.GlobalLogger.Panic("CmpDistance tracer failed to update distance map during capture end", distanceUpdateErr)
	}
}

// OnOpcode records data from an EVM state update, as defined by tracers.Tracer.
func (t *CmpDistanceTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	// Obtain our call frame state tracking struct
	callFrameState := t.callFrameStates[t.callDepth]

	if !callFrameState.initialized {
		callFrameState.initialized = true
		callFrameState.address = scope.Address()
	}

	// If there is code we're executing and opcode is a comparison operation, collect distance information.
	if vm.OpCode(op) == vm.LT || vm.OpCode(op) == vm.GT || vm.OpCode(op) == vm.EQ || vm.OpCode(op) == vm.SLT || vm.OpCode(op) == vm.SGT {
		diff := uint256.NewInt(0)

		// We can cast OpContext to ScopeContext because that is the type passed to OnOpcode.
		scopeContext := scope.(*vm.ScopeContext)
		code := scopeContext.Contract.Code
		isCreate := callFrameState.create

		// Get stack values for comparison operations
		if len(scopeContext.Stack.Data()) >= 2 {
			x := scopeContext.Stack.Back(0)
			y := scopeContext.Stack.Back(1)
			if x.Gt(y) { // if x > y
				diff = diff.Sub(x, y)
			} else { // if x <= y
				diff = diff.Sub(y, x)
			}

			// Obtain our contract distance map lookup hash.
			if callFrameState.lookupHash == nil {
				lookupHash := getContractCmpDistanceMapHash(code, isCreate)
				callFrameState.lookupHash = &lookupHash
			}

			_, distanceUpdateErr := callFrameState.pendingCmpDistanceMap.SetAt(t.addressForCoverage(callFrameState.address), *callFrameState.lookupHash, pc, diff)
			if distanceUpdateErr != nil {
				logging.GlobalLogger.Panic("CmpDistance tracer failed to update distance map while tracing state", distanceUpdateErr)
			}
		}
	}
}

// CaptureTxEndSetAdditionalResults can be used to set additional results captured from execution tracing. If this
// tracer is used during transaction execution (block creation), the results can later be queried from the block.
// This method will only be called on the added tracer if it implements the extended TestChainTracer interface.
func (t *CmpDistanceTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Store our tracer results.
	results.AdditionalResults[cmpDistanceTracerResultsKey] = t.cmpDistanceMaps
}
