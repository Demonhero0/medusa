package branchcoverage

import (
	"bytes"
	"math/big"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core/tracing"
	coretypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa-geth/core/vm"
	"github.com/crytic/medusa-geth/eth/tracers"
	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/chain/types"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	fuzzerTypes "github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/logging"
)

// coverageTracerResultsKey describes the key to use when storing tracer results in call message results, or when
// querying them.
const coverageTracerResultsKey = "BranchCoverageTracerResults"

// GetCoverageTracerResults obtains CoverageMaps stored by a CoverageTracer from message results. This is nil if
// no CoverageMaps were recorded by a tracer (e.g. CoverageTracer was not attached during this message execution).
func GetCoverageTracerResults(messageResults *types.MessageResults) *CoverageMaps {
	// Try to obtain the results the tracer should've stored.
	if genericResult, ok := messageResults.AdditionalResults[coverageTracerResultsKey]; ok {
		if castedResult, ok := genericResult.(*CoverageMaps); ok {
			return castedResult
		}
	}

	// If we could not obtain them, return nil.
	return nil
}

// RemoveCoverageTracerResults removes CoverageMaps stored by a CoverageTracer from message results.
func RemoveCoverageTracerResults(messageResults *types.MessageResults) {
	delete(messageResults.AdditionalResults, coverageTracerResultsKey)
}

// CoverageTracer implements vm.EVMLogger to collect information such as coverage maps
// for fuzzing campaigns from EVM execution traces.
type CoverageTracer struct {
	// coverageMaps describes the execution coverage recorded. Call frames which errored are not recorded.
	coverageMaps *CoverageMaps

	// callFrameStates describes the state tracked by the tracer per call frame.
	callFrameStates []*coverageTracerCallFrameState

	// callDepth refers to the current EVM depth during tracing.
	callDepth int

	// evmContext holds the VM context during tracing
	evmContext *tracing.VMContext

	// nativeTracer is the underlying tracer used to capture EVM execution.
	nativeTracer *chain.TestChainTracer

	// branchMaps stores branch map for each contract code
	branchMaps map[common.Hash]*BranchMap

	// initialContractsSet records the set of contract addresses present in the base chain.
	initialContractsSet *map[common.Address]struct{}
}

// coverageTracerCallFrameState tracks state across call frames in the tracer.
type coverageTracerCallFrameState struct {
	// initialized tracks whether or not this has happened yet.
	initialized bool
	// create indicates whether the current call frame is executing on init bytecode (deploying a contract).
	create bool

	// pendingCoverageMap describes the coverage maps recorded for this call frame.
	pendingCoverageMap *CoverageMaps

	// lookupHash describes the hash used to look up the ContractCoverageMap being updated in this frame.
	lookupHash *common.Hash

	// address is used by OnOpcode to cache the result of scope.Address(), which is slow.
	// It records the address of the current contract.
	address common.Address
}

// NewCoverageTracer returns a new CoverageTracer.
func NewCoverageTracer(contracts fuzzerTypes.Contracts) *CoverageTracer {
	// Create a map of block maps for each contract code
	branchMaps := make(map[common.Hash]*BranchMap)
	for _, contract := range contracts {
		compiledContract := contract.CompiledContract()

		initBytecode := compiledContract.InitBytecode
		runtimeBytecode := compiledContract.RuntimeBytecode

		if initBytecode != nil {
			initBytecodeHash := getContractCoverageMapHash(initBytecode, true)
			// remove runtime bytecode (including metadata here) from init bytecode
			runtimeBytecodeOffset := bytes.LastIndex(initBytecode, runtimeBytecode)
			if runtimeBytecodeOffset != -1 {
				initBytecode = initBytecode[:runtimeBytecodeOffset]
			}
			branchMaps[initBytecodeHash] = GetBranchMapFromBytecode(initBytecode)
		}

		runtimeBytecodeHash := getContractCoverageMapHash(runtimeBytecode, false)
		// remove metadata from runtime bytecode
		runtimeBytecode = compilationTypes.RemoveContractMetadata(runtimeBytecode)
		branchMaps[runtimeBytecodeHash] = GetBranchMapFromBytecode(runtimeBytecode)
	}

	tracer := &CoverageTracer{
		coverageMaps:    NewCoverageMaps(),
		callFrameStates: make([]*coverageTracerCallFrameState, 0),
		branchMaps:      branchMaps,
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
func (t *CoverageTracer) NativeTracer() *chain.TestChainTracer {
	return t.nativeTracer
}

// SetInitialContractsSet sets the initialContractsSet value (see above).
func (t *CoverageTracer) SetInitialContractsSet(initialContractsSet *map[common.Address]struct{}) {
	t.initialContractsSet = initialContractsSet
}

// BLANK_ADDRESS is an all-zero address; it's a global var so that we don't have to recalculate (and reallocate) it every time.
var BLANK_ADDRESS = common.BytesToAddress([]byte{})

// addressForCoverage modifies an address based on the initialContractsSet value.
// This is applied to all addresses before they are recorded in the coverage map.
// If t.initialContractsSet is nil, we preserve all addresses.
// If t.initialContractsSet is defined, we only preserve addresses present in this set.
// Addresses not present in this set are zeroed to prevent issues with infinitely growing corpus.
func (t *CoverageTracer) addressForCoverage(address common.Address) common.Address {
	if t.initialContractsSet == nil {
		return address
	} else if _, ok := (*t.initialContractsSet)[address]; ok {
		return address
	} else {
		return BLANK_ADDRESS
	}
}

// OnTxStart is called upon the start of transaction execution, as defined by tracers.Tracer.
func (t *CoverageTracer) OnTxStart(vm *tracing.VMContext, tx *coretypes.Transaction, from common.Address) {
	// Reset our call frame states
	t.callDepth = 0
	t.coverageMaps = NewCoverageMaps()
	t.callFrameStates = make([]*coverageTracerCallFrameState, 0)
	t.evmContext = vm
}

// OnEnter is called upon entering of the call frame, as defined by tracers.Tracer.
func (t *CoverageTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	isTopLevelFrame := depth == 0
	if !isTopLevelFrame {
		t.callDepth++
	}
	// Create our state tracking struct for this frame.
	t.callFrameStates = append(t.callFrameStates, &coverageTracerCallFrameState{
		create:             typ == byte(vm.CREATE) || typ == byte(vm.CREATE2),
		pendingCoverageMap: NewCoverageMaps(),
	})
}

// OnExit is called upon exiting of the call frame, as defined by tracers.Tracer.
func (t *CoverageTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	currentCallFrameState := t.callFrameStates[t.callDepth]
	currentCoverageMap := currentCallFrameState.pendingCoverageMap

	if reverted {
		currentCoverageMap.RevertAll()
	}

	// Check to see if this is the top level call frame
	isTopLevelFrame := depth == 0

	// Commit all our coverage maps up one call frame.
	if isTopLevelFrame {
		_, coverageUpdateErr := t.coverageMaps.Update(currentCoverageMap)
		if coverageUpdateErr != nil {
			logging.GlobalLogger.Panic("Branch coverage tracer failed to update coverage map during capture end", coverageUpdateErr)
		}
	} else {
		// Move coverage up one call frame
		_, coverageUpdateErr := t.callFrameStates[t.callDepth-1].pendingCoverageMap.Update(currentCoverageMap)
		if coverageUpdateErr != nil {
			logging.GlobalLogger.Panic("Branch coverage tracer failed to update coverage map during capture exit", coverageUpdateErr)
		}

		// Pop the state tracking struct for this call frame off the stack and decrement the call depth
		t.callFrameStates = t.callFrameStates[:t.callDepth]
		t.callDepth--
	}
}

// OnOpcode records data from an EVM state update, as defined by tracers.Tracer.
func (t *CoverageTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	// Obtain our call frame state tracking struct
	callFrameState := t.callFrameStates[t.callDepth]

	if !callFrameState.initialized {
		callFrameState.initialized = true
		callFrameState.address = scope.Address()
	}

	scopeContext := scope.(*vm.ScopeContext)

	// If there is code we're executing and opcode is JUMPI, collect coverage.
	if len(scopeContext.Contract.Code) > 0 && vm.OpCode(op) == vm.JUMPI {
		// Obtain our contract coverage map lookup hash.
		if callFrameState.lookupHash == nil {
			lookupHash := getContractCoverageMapHash(scopeContext.Contract.Code, callFrameState.create)
			callFrameState.lookupHash = &lookupHash
		}

		// Obtain branch id using condition from stack.
		cond := !scopeContext.Stack.Back(1).IsZero()
		branchMap, exists := t.branchMaps[*callFrameState.lookupHash]
		if !exists {
			// This contract is not in our list of contracts to trace.
			return
		}
		branchSize := branchMap.Size()
		branchId := branchMap.GetBranchId(pc, cond)

		// Record branch coverage for this path of this instruction location in our map.
		_, coverageUpdateErr := callFrameState.pendingCoverageMap.SetAt(t.addressForCoverage(callFrameState.address), *callFrameState.lookupHash, branchSize, branchId)
		if coverageUpdateErr != nil {
			logging.GlobalLogger.Panic("Coverage tracer failed to update coverage map while tracing state", coverageUpdateErr)
		}
	}
}

// CaptureTxEndSetAdditionalResults can be used to set additional results captured from execution tracing. If this
// tracer is used during transaction execution (block creation), the results can later be queried from the block.
// This method will only be called on the added tracer if it implements the extended TestChainTracer interface.
func (t *CoverageTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Store our tracer results.
	results.AdditionalResults[coverageTracerResultsKey] = t.coverageMaps
}
